package lifecycle

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/localipc"
)

// renewalGate holds Control's lease renewals on their way to the engine, the
// way an overloaded PC did on 2026-11-23: the engine still gets each renewal,
// only late.
type renewalGate struct {
	mu      sync.Mutex
	delay   time.Duration
	hold    chan struct{} // when set, renewals wait until it is closed
	renewed atomic.Int64  // renewals written to the engine
	dials   atomic.Int64
}

type gatedConn struct {
	io.ReadWriteCloser
	gate *renewalGate
}

func (c *gatedConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"method":"renew"`)) {
		c.gate.mu.Lock()
		delay, hold := c.gate.delay, c.gate.hold
		c.gate.mu.Unlock()
		if hold != nil {
			<-hold
		}
		time.Sleep(delay)
		defer c.gate.renewed.Add(1)
	}
	return c.ReadWriteCloser.Write(p)
}

func (g *renewalGate) set(delay time.Duration, hold chan struct{}) {
	g.mu.Lock()
	g.delay, g.hold = delay, hold
	g.mu.Unlock()
}

func gatedFixture(t *testing.T) (*nativeFixture, *renewalGate) {
	t.Helper()
	f := newNativeFixture(t, nativeProber{})
	gate := &renewalGate{}
	inner := f.remote.dial
	f.remote.dial = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		c, err := inner(ctx, e)
		if err != nil {
			return nil, err
		}
		gate.dials.Add(1)
		return &localipc.Conn{ReadWriteCloser: &gatedConn{ReadWriteCloser: c.ReadWriteCloser, gate: gate}, Peer: c.Peer}, nil
	}
	// The real timing scaled down 250 times: every 5 s, slow after 4 s, give
	// up 20 s after the last renewal that landed.
	f.remote.renewal = renewalTiming{every: 20 * time.Millisecond, timeout: 16 * time.Millisecond, giveUp: 80 * time.Millisecond}
	return f, gate
}

// 2026-11-23: renewals took longer than their 4 s request deadline while a
// native build starved the PC. Control tore the working connection down at the
// first one, the reattach could not finish within the 30 s lease, and the
// engine stopped routing ten times in 45 minutes.
func TestSlowLeaseRenewalsKeepTheConnection(t *testing.T) {
	f, gate := gatedFixture(t)
	if err := f.remote.Attach(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	f.remote.mu.Lock()
	attached := f.remote.rpc
	f.remote.mu.Unlock()
	// Every renewal now takes 2.5 times the slow threshold but lands within
	// the lease budget.
	gate.set(40*time.Millisecond, nil)
	waitFor(t, "ten slow renewals", func() bool { return gate.renewed.Load() >= 10 })
	f.remote.mu.Lock()
	still := f.remote.rpc
	f.remote.mu.Unlock()
	if still != attached || gate.dials.Load() != 1 || f.hasLog("engine transport interrupted") {
		t.Fatalf("slow renewals ended the connection: same=%v dials=%d", still == attached, gate.dials.Load())
	}
	if !f.hasLog("engine lease renewal is slow") || !f.hasLog("engine lease renewed after") {
		t.Fatal("slow renewals were not logged")
	}
}

// A renewal that never lands still ends the connection once the lease budget
// is spent, so a hung engine is still found.
func TestLeaseRenewalThatNeverLandsDisconnectsWithinTheBudget(t *testing.T) {
	f, gate := gatedFixture(t)
	if err := f.remote.Attach(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	gate.set(0, hold)
	started := time.Now()
	waitFor(t, "the disconnect", func() bool { return f.hasLog("engine transport interrupted") })
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("a renewal that never lands held the connection for %s", took)
	}
	if !f.hasLog("no lease renewal for") {
		t.Fatal("disconnect does not say how long the lease went unrenewed")
	}
}

// A closed connection is not a slow one: Control notices at once.
func TestClosedEngineConnectionStillDisconnectsAtOnce(t *testing.T) {
	f, _ := gatedFixture(t)
	if err := f.remote.Attach(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	f.remote.mu.Lock()
	rpc := f.remote.rpc
	f.remote.mu.Unlock()
	rpc.Close()
	waitFor(t, "the disconnect", func() bool { return f.hasLog("engine transport interrupted") })
	if f.hasLog("engine lease renewal is slow") {
		t.Fatal("a closed connection was treated as a slow renewal")
	}
}
