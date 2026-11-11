package ownerbpf

import (
	"sync"
	"sync/atomic"
)

// ActorSyncGate closes the visibility gap between popping queued actor events
// from the eBPF queue (which clears HasPendingNewActors) and publishing the
// resulting socket-slot entries in ProvenanceRuntime. Without holding inFlight
// across both steps, a concurrent TUN burst reader can observe
// HasPendingNewActors() == false while a background retire or reconcile sweep
// is still enriching /proc metadata and publishing slots, causing transient
// IdentityUnretained lookups on newly opened sockets.
type ActorSyncGate struct {
	mu       sync.Mutex
	inFlight atomic.Int64
}

func (g *ActorSyncGate) Sync(
	isPoisoned func() bool,
	onPoison func(),
	hasPending func() bool,
	drainAndSync func() error,
) error {
	if isPoisoned != nil && isPoisoned() && onPoison != nil {
		onPoison()
	}
	// Check hasPending BEFORE inFlight so a drain that starts and clears
	// hasPending concurrently either leaves hasPending true or already bumped
	// inFlight > 0 before clearing hasPending.
	if (hasPending == nil || !hasPending()) && g.inFlight.Load() == 0 {
		return nil
	}

	g.mu.Lock()
	g.inFlight.Add(1)
	defer func() {
		g.inFlight.Add(-1)
		g.mu.Unlock()
	}()

	if isPoisoned != nil && isPoisoned() && onPoison != nil {
		onPoison()
	}
	if hasPending != nil && !hasPending() {
		return nil
	}
	var err error
	if drainAndSync != nil {
		err = drainAndSync()
	}
	if isPoisoned != nil && isPoisoned() && onPoison != nil {
		onPoison()
	}
	return err
}
