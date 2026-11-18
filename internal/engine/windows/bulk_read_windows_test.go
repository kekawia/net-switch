//go:build windows

package winengine

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestBulkReadNotificationsLeaveFreshSocketsImmediate(t *testing.T) {
	p := &readiness{stop: make(chan struct{}), batch: make(map[*socketWatch]struct{}), batchWake: make(chan struct{}, 1)}
	var calls atomic.Int32
	done := make(chan struct{}, 1)
	bulk := &socketWatch{pool: p, wake: func() { calls.Add(1); done <- struct{}{} }}
	bulk.bulkUntil.Store(int64(time.Since(relayClockStart) + time.Minute))
	bulk.readable(bulk.wake)
	bulk.readable(bulk.wake)
	if len(p.batch) != 1 || calls.Load() != 0 {
		t.Fatal("bulk notifications did not coalesce")
	}
	fresh := &socketWatch{pool: p}
	immediate := false
	fresh.readable(func() { immediate = true })
	if !immediate {
		t.Fatal("a fresh socket waited behind a bulk transfer")
	}
	removed := &socketWatch{pool: p, detached: true, wake: func() { t.Error("detached socket signalled") }}
	removed.bulkUntil.Store(bulk.bulkUntil.Load())
	removed.readable(removed.wake)
	p.wg.Go(p.deliverBulkReads)
	defer func() { close(p.stop); p.wg.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bulk notification lost")
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate bulk notification")
	}
}

func TestBulkReadRequiresRecentVolume(t *testing.T) {
	c := &readySocket{watch: &socketWatch{}}
	for i := range 128 {
		c.noteRead(time.Duration(i)*bulkReadWindow, 1024)
	}
	if c.watch.bulkUntil.Load() != 0 {
		t.Fatal("a low-rate stream acquired a batching delay")
	}
	now := 128 * bulkReadWindow
	for range 64 {
		c.noteRead(now, 1024)
	}
	expiry := c.watch.bulkUntil.Load()
	if expiry != int64(now+bulkReadWindow) {
		t.Fatal("a fragmented bulk transfer was not recognized")
	}
	c.noteRead(now+2*bulkReadWindow, 1)
	if c.watch.bulkUntil.Load() != expiry {
		t.Fatal("an interactive exchange after idle extended the batch window")
	}
}
