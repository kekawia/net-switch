package tcp

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/engine/flows"
	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/kekawia/net-switch/internal/engine/policy"
	"github.com/kekawia/net-switch/internal/engine/testfake"
)

type setupReport struct {
	line string
	dst  netip.Addr
	took time.Duration
}

type setupRecorder struct {
	*flows.Table
	mu      sync.Mutex
	reports []setupReport
}

func (c *setupRecorder) LineConnected(line string, dst netip.Addr, took time.Duration) {
	c.mu.Lock()
	c.reports = append(c.reports, setupReport{line, dst, took})
	c.mu.Unlock()
	c.Table.LineConnected(line, dst, took)
}

func (c *setupRecorder) snapshot() []setupReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]setupReport(nil), c.reports...)
}

func newSetupRecorder(t *testing.T) *setupRecorder {
	t.Helper()
	c := &setupRecorder{Table: flows.New(flows.Defaults(), nil)}
	config := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	if _, err := c.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	return c
}

// Auto balancing judges a full queue by how long dials take, so the forwarder
// must report every successful dial with its line, server and duration.
func TestForwarderReportsDialSetupTime(t *testing.T) {
	c := newSetupRecorder(t)
	remote, server := testfake.Pair()
	defer server.Close()
	const delay = 40 * time.Millisecond
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		time.Sleep(delay)
		return remote, nil
	}}
	_, dial := harness(t, c, d)
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(c.snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := c.snapshot()
	if len(got) != 1 {
		t.Fatalf("want one setup report, got %+v", got)
	}
	if r := got[0]; r.line != "A" || r.dst != netip.MustParseAddr("203.0.113.7") || r.took < delay || r.took > 2*time.Second {
		t.Fatalf("setup report %+v, want line A, 203.0.113.7 and at least %v", r, delay)
	}
}

func TestForwarderReportsNoSetupTimeForFailedDial(t *testing.T) {
	c := newSetupRecorder(t)
	dialed := make(chan struct{})
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		defer close(dialed)
		return nil, errors.New("connection refused")
	}}
	_, dial := harness(t, c, d)
	if app, err := dial(); err == nil {
		app.Close()
		t.Fatal("dial to a refused server should fail")
	}
	<-dialed
	if got := c.snapshot(); len(got) != 0 {
		t.Fatalf("a failed dial must not report a setup time, got %+v", got)
	}
}
