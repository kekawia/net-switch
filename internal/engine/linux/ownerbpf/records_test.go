package ownerbpf

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestWireABI(t *testing.T) {
	for _, c := range []struct {
		value any
		size  int
	}{
		{ActorKey{}, 32}, {ActorEvidence{}, 32}, {TupleKey{}, 12}, {TupleEvidence{}, 16},
	} {
		if got := binary.Size(c.value); got != c.size {
			t.Fatalf("%T: %d, want %d", c.value, got, c.size)
		}
	}
}

func TestUnsafeEvidenceNeverFallsBackToCurrentHolder(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		counts Counters
		tuple  *TupleEvidence
		status Status
	}{
		{Counters{}, nil, Missing},
		{Counters{}, &TupleEvidence{FirstCookie: 41}, IncompleteIdentity},
		{Counters{}, &TupleEvidence{FirstCookie: 41, Conflicts: 1}, AmbiguousGeneration},
		// An insertion failure must invalidate an EXISTING stale known candidate,
		// including if the poison-counter write wasn't observed yet.
		{Counters{InsertFailure: 1}, &TupleEvidence{FirstCookie: 41}, Poisoned},
		{Counters{Poison: 1}, nil, Poisoned},
	} {
		r := Decide(ctx, time.Now(), c.counts, c.tuple)
		if r.Status != c.status || r.AllowsScanner() != (c.status == Missing) {
			t.Fatalf("%+v -> %+v", c, r)
		}
	}
}

func TestSharedDeadlineCannotBeRenewedByEvidence(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if got := Decide(ctx, deadline, Counters{}, &TupleEvidence{FirstCookie: 1}); got.Status != Expired || got.AllowsScanner() {
		t.Fatal(got)
	}
}

func TestQueuedTupleCounterexample(t *testing.T) {
	// A queued datagram contains the same tuple and bytes whether it came
	// from generation 41 or 42. Latest-cookie lookup gives 42 in both worlds.
	// No function of those inputs can return the right generation in both.
	packetA, packetB := [4]byte{1, 2, 3, 4}, [4]byte{1, 2, 3, 4}
	latest := uint64(42)
	if packetA != packetB || latest == 41 {
		t.Fatal("bad counterexample precondition")
	}
	// Retaining both generations detects ambiguity; elapsed time is no proof
	// that either queued packet was consumed. This API has no TTL escape hatch.
	for _, elapsed := range []time.Duration{0, time.Second, 24 * time.Hour} {
		r := Decide(context.Background(), time.Now().Add(elapsed), Counters{}, &TupleEvidence{41, 1})
		if r.Status != AmbiguousGeneration || r.AllowsScanner() {
			t.Fatal(r)
		}
	}
}
