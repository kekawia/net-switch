package control

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Spec §2: every failed start attempt counts toward the backoff (1, 2, 5, then
// 30 s) and the five-in-ten-minutes latch, unless it is one of the free cases
// (a lease-expired stop, the adapter-loss window). A start the engine refuses
// with an error while its instance keeps running is an ordinary failure. On
// main it was not: the Windows lifecycle run retried such a start every 1.3 s
// for a minute, because every refusal looked like the first one.
func TestRefusedStartsBackOffAndLatch(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e.refuse = errors.New("native revision history cannot go backwards or change its hash")
	ctx := context.Background()
	starts := func() int {
		n := 0
		for _, call := range e.calls {
			if call == "start" {
				n++
			}
		}
		return n
	}
	_ = c.Routing(ctx, true)
	if starts() != 1 || len(c.failureTimes) != 1 {
		t.Fatalf("first refused start: starts=%d failures=%v", starts(), c.failureTimes)
	}
	// Supervise returns the refusal of the start it ran; the schedule is
	// what matters here.
	for i, delay := range []int64{1000, 2000, 5000, 30000} {
		clock.advance(delay - 1)
		for poll := 0; poll < 3; poll++ {
			_ = c.Supervise(ctx)
		}
		if starts() != i+1 {
			t.Fatalf("retried %d ms after refusal %d, before its %d ms backoff", delay-1, i+1, delay)
		}
		clock.advance(1)
		_ = c.Supervise(ctx)
		if starts() != i+2 {
			t.Fatalf("no retry once the %d ms backoff after refusal %d had passed (starts=%d)", delay, i+1, starts())
		}
		if len(c.failureTimes) != i+2 {
			t.Fatalf("refusal %d was not counted: %v", i+2, c.failureTimes)
		}
	}
	s := e.Snapshot()
	if s.Status != "error" || s.Error == nil || !strings.Contains(*s.Error, "five failures") {
		t.Fatalf("fifth refusal did not latch: %+v", s)
	}
	clock.advance(10 * 60000)
	for poll := 0; poll < 3; poll++ {
		_ = c.Supervise(ctx)
	}
	if starts() != 5 {
		t.Fatal("latched routing retried on its own", starts())
	}
	// Turning routing on again is a fresh intent with a full budget.
	e.refuse = nil
	if err := c.Routing(ctx, true); err != nil {
		t.Fatal(err)
	}
	if starts() != 6 || e.Snapshot().Status != "on" || len(c.failureTimes) != 0 {
		t.Fatalf("fresh intent after the latch: starts=%d status=%s failures=%v", starts(), e.Snapshot().Status, c.failureTimes)
	}
}

// A refusal is counted once, from Start's own result. The engine keeps
// showing the error until the retry; polls that read it before the retry
// runs count nothing, and a retry that succeeds leaves exactly the one
// failure that happened. On the earlier design the poll minted the
// instance's failure identity and counted the same refusal a second time.
func TestPolledRefusalErrorIsShownNotCounted(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	e.refuse = errors.New("native revision history cannot go backwards or change its hash")
	ctx := context.Background()
	_ = c.Routing(ctx, true)
	if len(c.failureTimes) != 1 {
		t.Fatal("refused start not counted once", c.failureTimes)
	}
	// Polls before the 1 s backoff: the engine still reports the error.
	for poll := 0; poll < 4; poll++ {
		clock.advance(200)
		_ = c.Supervise(ctx)
		c.mu.Lock()
		c.statusLocked(e.Snapshot())
		c.mu.Unlock()
	}
	if len(c.failureTimes) != 1 || e.refusals != 1 {
		t.Fatalf("polling the shown error counted it again: failures=%v refusals=%d", c.failureTimes, e.refusals)
	}
	// The retry succeeds: no failure is added, and the status is on.
	e.refuse = nil
	clock.advance(300)
	if err := c.Supervise(ctx); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Status != "on" || len(c.failureTimes) != 1 {
		t.Fatalf("successful retry after a shown refusal: status=%s failures=%v", e.Snapshot().Status, c.failureTimes)
	}
	// A refused retry counts exactly one more.
	if err := c.Routing(ctx, false); err != nil {
		t.Fatal(err)
	}
	e.refuse = errors.New("refused again")
	_ = c.Routing(ctx, true)
	c.mu.Lock()
	c.statusLocked(e.Snapshot())
	c.statusLocked(e.Snapshot())
	c.mu.Unlock()
	if len(c.failureTimes) != 1 {
		t.Fatalf("a refused retry under a fresh intent did not count exactly once: %v", c.failureTimes)
	}
}
