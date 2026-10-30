package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

type replayAckRuntime struct {
	*nativeRuntime
	mu        sync.Mutex
	mode      string
	revisions []policy.Revision
	committed chan policy.Applied
	release   chan struct{}
}

func (r *replayAckRuntime) Apply(ctx context.Context, v policy.Revision) (policy.Applied, error) {
	r.mu.Lock()
	mode := r.mode
	r.revisions = append(r.revisions, v)
	r.mu.Unlock()
	a, err := r.nativeRuntime.Apply(ctx, v)
	if err != nil {
		return a, err
	}
	switch mode {
	case "number":
		a.N++
	case "hash":
		a.Hash = "mismatched-native-hash"
	case "lost":
		r.committed <- a
		select {
		case <-r.release:
		case <-ctx.Done():
			return policy.Applied{}, ctx.Err()
		}
	}
	return a, nil
}

func TestNativeApplyAcknowledgementRecovery(t *testing.T) {
	for _, mode := range []string{"number", "hash", "lost"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t, nativeProber{})
			fault := &replayAckRuntime{nativeRuntime: f.runtime, committed: make(chan policy.Applied, 1), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(fault.release) })
			defer release()
			f.dialMu.Lock()
			f.server = protocol.New(fault, f.runtime.table, nativeProber{})
			f.dialMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first := testRevision(1)
			f.remote.Restore(&first)
			if err := f.remote.Start(ctx, first.Policy); err != nil {
				t.Fatal(err)
			}
			before := f.remote.Snapshot()
			if before.Status != "on" || before.AppliedRevision != 1 || before.AppliedPoint == 0 {
				t.Fatal("ack starting state", before)
			}
			ticket, err := f.runtime.table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ticket.Resolve(platform.Owner{AppID: "held", Path: "held"}); err != nil {
				t.Fatal(err)
			}
			ticket.SetCancel(ticket.Close)
			defer ticket.Close()
			held, err := f.runtime.table.Page("")
			if err != nil || len(held.Flows) != 1 {
				t.Fatal("held flow missing", err)
			}
			next := testRevision(2)
			next.Policy.IPv6 = true
			fault.mu.Lock()
			fault.mode = mode
			fault.mu.Unlock()
			if mode == "lost" {
				requestCtx, stop := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { _, err := f.remote.Apply(requestCtx, next); done <- err }()
				select {
				case applied := <-fault.committed:
					if applied.N != 2 || applied.Point <= before.AppliedPoint {
						t.Fatal("mutation never committed", applied)
					}
				case <-ctx.Done():
					t.Fatal("apply did not commit")
				}
				stop()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("lost acknowledgement accepted")
					}
				case <-ctx.Done():
					t.Fatal("cancelled apply did not return")
				}
				release()
			} else if _, err := f.remote.Apply(ctx, next); err == nil {
				t.Fatal("mismatched acknowledgement accepted")
			}
			if !reflect.DeepEqual(f.remote.Snapshot(), before) {
				t.Fatal("unacknowledged policy published", f.remote.Snapshot())
			}
			applied := f.runtime.table.Applied()
			if applied == nil || applied.N != 2 || applied.Point <= before.AppliedPoint {
				t.Fatal("actual apply was not exercised", applied)
			}
			point := applied.Point
			fault.mu.Lock()
			fault.mode = ""
			fault.mu.Unlock()
			ack, err := f.remote.Apply(ctx, next)
			if err != nil {
				t.Fatal(err)
			}
			if ack.Number != 2 || ack.Hash != next.Hash || ack.Instance != f.server.Instance || ack.Point != point {
				t.Fatal("retry changed committed revision/point", ack, point)
			}
			after := f.remote.Snapshot()
			if after.AppliedRevision != 2 || after.AppliedHash != next.Hash || after.AppliedPoint != point || !after.Policy.IPv6 || after.FailureID != "" || after.Status != "on" {
				t.Fatal("retry publication", after)
			}
			fault.mu.Lock()
			requests := append([]policy.Revision{}, fault.revisions...)
			fault.mu.Unlock()
			if len(requests) != 2 || !reflect.DeepEqual(requests[0], requests[1]) {
				t.Fatal("retry replaced the desired revision", requests)
			}
			survivors, err := f.runtime.table.Page("")
			if err != nil || !reflect.DeepEqual(survivors.Flows, held.Flows) {
				t.Fatal("ack fault disturbed held flows", err)
			}
		})
	}
}

// More than two real 64-record pages travel through Remote.Connections. Every
// ID and both counters are checked; no canned page is supplied to the client.
func TestNativeFlowPaginationReplacement(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	ctx := context.Background()
	rev := testRevision(1)
	f.remote.Restore(&rev)
	if err := f.remote.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	if page, err := f.runtime.table.Page(""); err != nil || len(page.Flows) != 0 {
		t.Fatal("pagination starting table", err)
	}
	const count = 4096
	for i := 1; i <= count; i++ {
		ticket, err := f.runtime.table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(fmt.Sprintf("198.18.0.2:%d", 40000+i)), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ticket.Resolve(platform.Owner{AppID: "page-app", Path: strings.Repeat("folder/", 40) + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
		ticket.Established(netip.MustParseAddr("192.0.2.1"))
		ticket.Add(uint64(i), uint64(2*i))
		ticket.SetCancel(ticket.Close)
		defer ticket.Close()
	}
	page, err := f.runtime.table.Page("")
	if err != nil || len(page.Flows) != 64 || page.Cursor == "" {
		t.Fatal("pagination precondition", len(page.Flows), page.Cursor, err)
	}
	all := append(page.Flows[:0:0], page.Flows...)
	for page.Cursor != "" {
		page, err = f.runtime.table.Page(page.Cursor)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Flows...)
	}
	encoded, err := json.Marshal(all)
	if err != nil || len(all) != count || len(encoded) <= protocol.MessageLimit {
		t.Fatal("snapshot did not exceed one frame", len(encoded), err)
	}
	got, err := f.remote.Connections(ctx)
	if err != nil || len(got) != count {
		t.Fatal("native pagination truncated", len(got), err)
	}
	seen := map[string]bool{}
	for i, v := range got {
		want := strconv.Itoa(i + 1)
		if seen[v.ID] || v.ID != want || v.Upload != float64(i+1) || v.Download != float64(2*(i+1)) || v.AppID != "page-app" || v.Metadata.ProcessPath != strings.Repeat("folder/", 40)+want || len(v.Chains) != 1 || v.Start == "" {
			t.Fatal("paged native record", i, v)
		}
		seen[v.ID] = true
	}
	t.Logf("native snapshot: %d records, %d bytes before paging", count, len(encoded))
	if f.remote.Snapshot().AppliedRevision != 1 {
		t.Fatal("read changed revision")
	}
}

// Only the hello is changed; requests still reach the real native server.
type replayHelloConn struct {
	net.Conn
	mode string
}

func (c replayHelloConn) Write(b []byte) (int, error) {
	original := len(b)
	var reply map[string]any
	if json.Unmarshal(b, &reply) == nil {
		if result, ok := reply["result"].(map[string]any); ok && result["capabilities"] != nil {
			switch c.mode {
			case "version":
				result["version"] = "incompatible-replay-version"
			case "adapter":
				result["capabilities"] = []string{"singbox-adapter-v1"}
			case "missing":
				result["capabilities"] = []string{"revisions", "lease", "status"}
			}
			var err error
			b, err = json.Marshal(reply)
			if err != nil {
				return 0, err
			}
			b = append(b, '\n')
		}
	}
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	return original, nil
}

func TestNativeHelloRejectionBeforeAttach(t *testing.T) {
	for _, mode := range []string{"version", "adapter", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t, nativeProber{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var serving sync.WaitGroup
			f.remote.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
				left, right := net.Pipe()
				serving.Add(1)
				go func() { defer serving.Done(); _ = f.server.Serve(ctx, replayHelloConn{left, mode}) }()
				return &localipc.Conn{ReadWriteCloser: right}, nil
			}
			defer func() { cancel(); serving.Wait() }()
			if err := f.remote.Attach(ctx, false); err == nil {
				t.Error("incompatible hello was accepted")
			}
			f.remote.mu.Lock()
			rpc, epoch := f.remote.rpc, f.remote.epoch
			f.remote.mu.Unlock()
			if rpc != nil || epoch != 0 {
				t.Error("rejected hello published an attachment")
			}
			// The first valid attachment must still receive epoch 1. This would be
			// 2 if the rejected handshake reached attach on the real server.
			reply := f.server.Handle(ctx, protocol.Request{ID: "witness", Method: "attach", Instance: f.server.Instance})
			if reply.Error != "" || reply.Result.(map[string]any)["epoch"] != uint64(1) {
				t.Error("rejected hello consumed attach epoch", reply)
			}
		})
	}
}
