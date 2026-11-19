package stack

import (
	"context"
	"sync/atomic"
	"testing"
)

func TestBatchLeaseSurvivesQueueCloseUntilWriterReleases(t *testing.T) {
	l := NewLink()
	defer l.Close()
	var released atomic.Int32
	done := func() {
		if !l.mu.TryLock() {
			t.Error("release callback held queue lock")
		} else {
			l.mu.Unlock()
		}
		released.Add(1)
	}
	if !l.SendBatch([][]byte{{1}, {2}}, done) {
		t.Fatal("batch refused")
	}
	var held [1]OutputPacket
	if l.ReadOwnedBatch(context.Background(), held[:]) != 1 || l.Queued() != 1 {
		t.Fatal("fixture must have one packet queued and one writer-owned")
	}
	l.Close()
	if released.Load() != 0 {
		t.Fatal("queue shutdown released bytes still owned by writer")
	}
	held[0].Release()
	held[0].Release()
	if released.Load() != 1 {
		t.Fatalf("batch released %d times", released.Load())
	}
}

func TestBatchQueueReservationIsAtomic(t *testing.T) {
	l := NewLink()
	defer l.Close()
	for range QueuePackets - 1 {
		if !l.Send([]byte{7}) {
			t.Fatal("fixture did not fill queue")
		}
	}
	var released atomic.Int32
	if l.SendBatch([][]byte{{1}, {2}}, func() { released.Add(1) }) {
		t.Fatal("partial batch was accepted")
	}
	if l.Queued() != QueuePackets-1 || released.Load() != 1 || l.Dropped.Load() != 2 {
		t.Fatal("rejected batch retained a fragment or its byte lease")
	}
}

func TestWriteBurstCoalescesReadySignal(t *testing.T) {
	l := NewLink()
	defer l.Close()

	// Nested burst holds ready signals until the outermost EndWriteBurst.
	l.BeginWriteBurst()
	l.BeginWriteBurst()
	for range 10 {
		if !l.Send([]byte{1, 2, 3}) {
			t.Fatal("Send refused during burst")
		}
	}
	select {
	case <-l.ready:
		t.Fatal("ready fired before burst ended")
	default:
	}
	l.EndWriteBurst()
	select {
	case <-l.ready:
		t.Fatal("ready fired before outermost burst ended")
	default:
	}
	l.EndWriteBurst()
	select {
	case <-l.ready:
	default:
		t.Fatal("EndWriteBurst did not signal queued packets")
	}
	var drained [64]OutputPacket
	n := l.ReadOwnedBatch(context.Background(), drained[:])
	if n != 10 {
		t.Fatalf("drained %d packets, want 10", n)
	}
	for i := range n {
		drained[i].Release()
	}

	// Once depth reaches 64 during a burst, ready fires immediately so the
	// TUN writer can start draining without waiting for EndWriteBurst.
	l.BeginWriteBurst()
	for range 64 {
		if !l.Send([]byte{4, 5, 6}) {
			t.Fatal("Send refused while reaching threshold")
		}
	}
	select {
	case <-l.ready:
	default:
		t.Fatal("ready did not fire when burst reached 64 queued packets")
	}
	l.EndWriteBurst()
}
