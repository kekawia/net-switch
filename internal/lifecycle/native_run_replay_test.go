package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	ep "github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
)

type nativeRunClock struct{ origin time.Time }

func (c nativeRunClock) Now() time.Time { return c.origin.Add(time.Since(c.origin) * 100) }
func (nativeRunClock) After(d time.Duration) <-chan time.Time {
	return time.After(max(time.Millisecond, d/100))
}

type nativeRunPlatform struct {
	clock             nativeRunClock
	streams, sequence atomic.Int64
}

func (p *nativeRunPlatform) Call(_ context.Context, op string, _ map[string]any) (any, error) {
	switch op {
	case "network":
		return map[string]any{"readAt": p.clock.Now().UnixMilli(), "policy": float64(1), "adapters": []any{map[string]any{"alias": "Ethernet", "status": "Up", "gateway": "192.0.2.254", "ipv4s": []any{"192.0.2.1"}}, map[string]any{"alias": "Wi-Fi", "status": "Up", "gateway": "192.0.2.254", "mediaType": "wireless", "ipv4s": []any{"192.0.2.2"}}}, "defaultRoutes": []any{map[string]any{"interfaceAddress": "192.0.2.1"}, map[string]any{"interfaceAddress": "192.0.2.2"}}}, nil
	case "elevated":
		return true, nil
	case "app-info", "installed-apps":
		return []any{}, nil
	case "close-tcp":
		return map[string]any{"closed": 0, "failed": 0, "gone": 0, "codes": []any{}}, nil
	default:
		return nil, fmt.Errorf("unexpected native Run platform operation %s", op)
	}
}
func (p *nativeRunPlatform) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	tick := time.NewTicker(4 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		var v any
		switch mode {
		case "network":
			v, _ = p.Call(ctx, "network", nil)
		case "meters":
			v = map[string]any{"adapters": []any{map[string]any{"alias": "Ethernet", "rx": p.sequence.Add(100), "tx": 0}}}
		case "outside":
			v = map[string]any{"outside": []any{}}
		default:
			report(fmt.Errorf("unexpected stream %s", mode))
			return
		}
		b, err := json.Marshal(v)
		if err != nil {
			report(err)
			return
		}
		p.streams.Add(1)
		emit(b)
	}
}

type countedNativeRemote struct {
	*Remote
	reads atomic.Int64
}

func (r *countedNativeRemote) Connections(ctx context.Context) ([]ce.Connection, error) {
	r.reads.Add(1)
	return r.Remote.Connections(ctx)
}

func TestNativeRunFourClientsFifteenActions(t *testing.T) {
	var probes atomic.Int64
	f := newNativeFixture(t, nativeProber{kind: func(r ep.ProbeRequest) string {
		probes.Add(1)
		if r.Quick {
			return "quick"
		}
		return "full"
	}})
	remote := &countedNativeRemote{Remote: f.remote}
	dir := t.TempDir()
	io := settings.Options{}
	store := settings.New(dir, io)
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	_, err := store.Update(map[string]any{"lines": []any{map[string]any{"id": "a1", "alias": "Ethernet", "label": "Ethernet", "kind": "wired", "weight": 1}, map[string]any{"id": "b2", "alias": "Wi-Fi", "label": "Wi-Fi", "kind": "wifi", "weight": 1}}, "appLines": apps.Pins{{Path: `C:\Apps\Firefox.exe`, LineID: "b2"}}})
	if err != nil {
		t.Fatal(err)
	}
	jopt := io
	jopt.FileName = "control-journal.json"
	jopt.Defaults = map[string]any{"revision": 0, "closures": []any{}}
	journal := settings.New(dir, jopt)
	if _, err := journal.Load(); err != nil {
		t.Fatal(err)
	}
	uopt := io
	uopt.FileName = "windows-undo.json"
	uopt.Defaults = map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}}
	undo := settings.New(dir, uopt)
	if _, err := undo.Load(); err != nil {
		t.Fatal(err)
	}
	clock := nativeRunClock{time.Now()}
	platform := &nativeRunPlatform{clock: clock}
	var tasks sync.WaitGroup
	var taskMu, logMu sync.Mutex
	closed := false
	logs := []string{}
	background := func(fn func()) {
		taskMu.Lock()
		defer taskMu.Unlock()
		if closed {
			return
		}
		tasks.Add(1)
		go func() { defer tasks.Done(); fn() }()
	}
	c, err := control.New(context.Background(), control.Options{ServiceMode: true, Engine: remote, Platform: platform, Settings: store, Journal: journal, Undo: undo, IO: io, Clock: clock, Mode: "tun", Version: "0.3.1", UserDir: dir, BootID: "native-run", Background: background, Log: func(s string) { logMu.Lock(); logs = append(logs, s); logMu.Unlock() }, CheckUpdate: func(context.Context) (*updates.Offer, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = c.Shutdown(context.Background())
		taskMu.Lock()
		closed = true
		taskMu.Unlock()
		tasks.Wait()
	}()
	c.CheckElevation(context.Background())
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if remote.Snapshot().Status == "on" || c.WantsRouting() {
		t.Fatal("Run precondition")
	}
	if err := c.SignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Run()
	wait := func(name string, predicate func() bool) {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for !predicate() {
			select {
			case <-deadline.C:
				t.Fatal(name)
			case <-tick.C:
			}
		}
	}
	wait("native Run did not start", func() bool { return remote.Snapshot().Status == "on" })
	ticket, err := f.runtime.table.Begin("tcp", ep.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ticket.Resolve(ep.Owner{AppID: engineAppIdentity(`C:\Apps\Firefox.exe`), Path: `C:\Apps\Firefox.exe`}); err != nil {
		t.Fatal(err)
	}
	ticket.Add(1, 10)
	ticket.SetCancel(ticket.Close)
	defer ticket.Close()
	wait("native Run did not discover app/stream/probe", func() bool {
		state := c.State()
		return len(state["apps"].([]any)) > 0 && remote.reads.Load() >= 10 && platform.streams.Load() >= 6 && probes.Load() >= 2
	})
	var clients sync.WaitGroup
	var completed atomic.Int64
	for client := 0; client < 4; client++ {
		clients.Add(1)
		go func(index int) {
			defer clients.Done()
			for i := 0; i < 15; i++ {
				var result any
				var err error
				switch index {
				case 0:
					result, err = c.Action(context.Background(), "POST", "/api/app-line", map[string]any{"path": `C:\Apps\Firefox.exe`, "line": "a1"})
				case 1:
					result, err = c.Action(context.Background(), "POST", "/api/reconnect", map[string]any{"key": `c:\apps\firefox.exe`})
				default:
					result = c.State()
				}
				if err != nil || result == nil {
					t.Errorf("client %d action %d: %v", index, i, err)
					return
				}
				completed.Add(1)
				time.Sleep(3 * time.Millisecond)
			}
		}(client)
	}
	clients.Wait()
	if completed.Load() != 60 {
		t.Fatal("missing concurrent actions", completed.Load())
	}
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	taskMu.Lock()
	closed = true
	taskMu.Unlock()
	tasks.Wait()
	if remote.Snapshot().Status != "off" || f.runtime.table.Applied() != nil {
		t.Fatal("native shutdown retained loaded policy")
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, s := range logs {
		if strings.Contains(s, "fatal control error") {
			t.Fatal(s)
		}
	}
	t.Logf("native Run: %d actions, %d starts, %d reads, %d streams, %d probes", completed.Load(), f.runtime.starts.Load(), remote.reads.Load(), platform.streams.Load(), probes.Load())
}
