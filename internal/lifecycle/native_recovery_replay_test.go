package lifecycle

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Recovery uses real native framing, fencing and revision storage. Only the OS
// service manager and packet runtime are replaced; no network device is opened.
type recoveryReplay struct {
	remote  *Remote
	server  *protocol.Server
	runtime *nativeRuntime
	mu      sync.Mutex
	logs    []string
}

func newRecoveryReplay(t *testing.T) *recoveryReplay {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	table := flows.New(flows.Defaults(), nil)
	f := &recoveryReplay{runtime: &nativeRuntime{table: table, started: time.Now()}}
	f.server = protocol.New(f.runtime, table, nativeProber{})
	r := NewRemote(ctx, func(message string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.logs = append(f.logs, message)
	})
	f.remote = r
	var serving sync.WaitGroup
	var dialMu sync.Mutex
	closed := false
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		if closed {
			return nil, context.Canceled
		}
		left, right := net.Pipe()
		serving.Add(1)
		go func() { defer serving.Done(); _ = f.server.Serve(ctx, left) }()
		return &localipc.Conn{ReadWriteCloser: right}, nil
	}
	r.queryService = func(string) (service.Status, error) {
		return service.Status{Running: true, PID: 4242}, nil
	}
	r.startService = func(context.Context, string) error { return nil }
	r.waitStopped = func(context.Context, string) error { return nil }
	// Any unexpected fall-through must never call the real service manager.
	r.forceStop = func(context.Context, string) error { return errors.New("unexpected forced stop") }
	t.Cleanup(func() {
		dialMu.Lock()
		closed = true
		cancel()
		dialMu.Unlock()
		r.mu.Lock()
		rpc := r.rpc
		r.mu.Unlock()
		if rpc != nil {
			rpc.Close()
		}
		done := make(chan struct{})
		go func() { serving.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native replay server did not join")
		}
		awaitRecovery(t, r, func() bool { return !r.recovering })
	})
	rev := testRevision(1)
	r.Restore(&rev)
	if err := r.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	if s := r.Snapshot(); s.Status != "on" || s.Instance != f.server.Instance || s.AppliedRevision != 1 {
		t.Fatalf("replay must begin with a loaded native instance: %+v", s)
	}
	return f
}

// predicate runs under Remote's state lock, so the test waits for publication,
// not merely for the server to have produced an answer.
func awaitRecovery(t *testing.T, r *Remote, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		ready := predicate()
		r.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("native recovery did not settle", r.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *recoveryReplay) interrupted() {
	f.remote.mu.Lock()
	rpc := f.remote.rpc
	f.remote.mu.Unlock()
	f.remote.disconnect(rpc, errors.New("replay transport interrupted"))
}

func (f *recoveryReplay) hasLog(fragment string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, message := range f.logs {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func TestNativeRecoveryReplayReattach(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	original := r.dial
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r.dial = func(ctx context.Context, endpoint localipc.Endpoint) (*localipc.Conn, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return original(ctx, endpoint)
	}
	f.interrupted()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no reattach attempt")
	}
	if s := r.Snapshot(); s.Status != "starting" || s.Instance != f.server.Instance || s.FailureID != "" || s.Error != nil {
		t.Fatal("held reconnect changed failure identity", s)
	}
	once.Do(func() { close(release) })
	awaitRecovery(t, r, func() bool {
		if r.snapshot.FailureID != "" || r.snapshot.Error != nil {
			t.Error("live native instance acquired a failure during reconnect")
		}
		return !r.recovering && r.snapshot.Status == "on" && f.hasLog("reattached to engine")
	})
	r.mu.Lock()
	epoch := r.epoch
	r.mu.Unlock()
	if s := r.Snapshot(); epoch != 2 || s.Instance != f.server.Instance || s.AppliedRevision != 1 || s.AppliedHash != testRevision(1).Hash || s.FailureID != "" || s.Error != nil {
		t.Fatal("native reattach lost revision or counted failure", epoch, s)
	}
	if !f.hasLog("engine transport interrupted") || !f.hasLog("reattached to engine") {
		t.Fatal("missing recovery diagnostics")
	}
	if err := r.call(r.ctx, "renew", nil, "", nil); err != nil {
		t.Fatal("reattached epoch cannot renew", err)
	}
	if reply := f.server.Handle(r.ctx, protocol.Request{ID: "old-renew", Method: "renew", Instance: f.server.Instance, Epoch: 1}); reply.Error == "" {
		t.Fatal("old epoch retained control after reattach")
	}
}

func TestNativeRecoveryReplayStaleServiceQuery(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	original := r.dial
	var refusing atomic.Bool
	r.dial = func(ctx context.Context, endpoint localipc.Endpoint) (*localipc.Conn, error) {
		if refusing.Load() {
			return nil, errors.New("old transport gone")
		}
		return original(ctx, endpoint)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r.queryService = func(string) (service.Status, error) {
		close(entered)
		<-release
		return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 1}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "failure"}, nil
	}
	refusing.Store(true)
	f.interrupted()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old query not reached")
	}
	refusing.Store(false)
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	awaitRecovery(t, r, func() bool { return !r.recovering })
	if s := r.Snapshot(); s.Status != "on" || s.Instance != f.server.Instance || s.FailureID != "" || s.Error != nil {
		t.Fatal("stale stopped query failed new attachment", s)
	}
}

func TestNativeRecoveryReplayFailureIdentity(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	r.failInstance(errors.New("observed instance failure"))
	id := r.Snapshot().FailureID
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) { return nil, errors.New("gone") }
	r.queryService = func(string) (service.Status, error) {
		return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 1}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "failure"}, nil
	}
	f.interrupted()
	awaitRecovery(t, r, func() bool { return !r.recovering })
	if s := r.Snapshot(); id != f.server.Instance || s.FailureID != id || s.Status != "error" {
		t.Fatal("one failed native instance produced multiple identities", id, s)
	}
}

func TestNativeRecoveryReplayForgetLane(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	// Hold the RPC request mutex: any IPC would block, including a call that
	// uses the existing connection instead of dialing again.
	r.rpc.mu.Lock()
	done := make(chan struct{})
	go func() { r.ForgetLane("b2"); close(done) }()
	select {
	case <-done:
		r.rpc.mu.Unlock()
	case <-time.After(time.Second):
		r.rpc.mu.Unlock()
		<-done
		t.Fatal("native ForgetLane performed IPC")
	}
	if s := r.Snapshot(); s.Policy.Lanes["b2"] != "b2" || s.AppliedRevision != 1 {
		t.Fatal("native revision was partially invalidated", s)
	}
}

func TestNativeRecoveryReplayAcknowledgedStop(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	var waited, forced bool
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	r.waitStopped = func(ctx context.Context, name string) error {
		waited = true
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Second || name != service.Engine {
			t.Error("unbounded or wrong service wait")
		}
		if state, _ := f.runtime.LiveState(); state != "off" {
			t.Error("wait preceded real native stop acknowledgement")
		}
		if f.runtime.table.Applied() != nil {
			t.Error("acknowledged native stop retained loaded policy")
		}
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	r.forceStop = func(ctx context.Context, name string) error {
		forced = true
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second || name != service.Engine {
			t.Error("unbounded or wrong forced cleanup")
		}
		if r.Snapshot().Status == "off" {
			t.Error("off published before forced cleanup")
		}
		return nil
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !waited || !forced || r.Snapshot().Status != "off" || !f.hasLog("terminating its service to fail open") {
		t.Fatal("bounded stop did not complete with diagnostics")
	}
}
func TestNativeRecoveryReplaySevenLeaseExits(t *testing.T) {
	for cycle := range 7 {
		t.Run(string(rune('1'+cycle)), func(t *testing.T) {
			f := newRecoveryReplay(t)
			r := f.remote
			r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
				return nil, errors.New("lease exited")
			}
			r.queryService = func(string) (service.Status, error) {
				return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}, nil
			}
			r.outcome = func(instance string) (host.Outcome, error) {
				if instance != f.server.Instance {
					t.Error("outcome requested for wrong instance")
				}
				return host.Outcome{Instance: instance, State: "complete", Reason: "lease-expired"}, nil
			}
			f.interrupted()
			awaitRecovery(t, r, func() bool { return !r.recovering })
			if s := r.Snapshot(); s.Status != "off" || s.FailureID != "" || s.Error != nil {
				t.Fatal("lease exit consumed failure identity", s)
			}
		})
	}
}
