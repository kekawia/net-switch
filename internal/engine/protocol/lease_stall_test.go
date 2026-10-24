package protocol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

type slowStopRuntime struct {
	runtimeFake
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *slowStopRuntime) Stop(ctx context.Context) error {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.runtimeFake.Stop(ctx)
}

// Only a lapsed lease may take the stall exit. A controller's explicit stop
// holds the same mutation lock for as long as its cleanup takes (the installed
// proof TestNativeEngineService/slow-start-and-clean-stop runs one of 15 s), so
// the lease loop waits for it, whether the lease is still valid or lapses
// while the cleanup runs. The first PR 2b push ended that legitimate stop
// after the 5 s stall bound; CI showed it as "long clean stop EOF".
func TestExplicitStopWithLongCleanupIsNotEndedByTheLease(t *testing.T) {
	for _, lapses := range []bool{false, true} {
		t.Run(map[bool]string{false: "lease-valid", true: "lease-lapses-during-cleanup"}[lapses], func(t *testing.T) {
			old := leaseStallBound
			leaseStallBound = 50 * time.Millisecond
			t.Cleanup(func() { leaseStallBound = old })
			table := flows.New(flows.Defaults(), nil)
			runtime := &slowStopRuntime{runtimeFake: runtimeFake{table: table}, entered: make(chan struct{}), release: make(chan struct{})}
			s := New(runtime, table, nil)
			s.OnLeaseStall = func(err error) { t.Error("explicit stop reported as a lease stall", err) }
			s.OnCleanupFailure = func(err error) { t.Error("explicit stop reported as a cleanup failure", err) }
			if r := s.Handle(context.Background(), Request{ID: "attach", Method: "attach", Instance: s.Instance}); r.Error != "" {
				t.Fatal(r.Error)
			}
			start := revision(1)
			if r := s.Handle(context.Background(), Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: 1, Revision: &start}); r.Error != "" {
				t.Fatal(r.Error)
			}
			stopped := make(chan Reply, 1)
			go func() {
				stopped <- s.Handle(context.Background(), Request{ID: "stop", Method: "stop", Instance: s.Instance, Epoch: 1})
			}()
			<-runtime.entered
			if lapses {
				s.mu.Lock()
				expired := s.expires.Add(time.Nanosecond)
				s.now = func() time.Time { return expired }
				s.mu.Unlock()
			}
			checked := make(chan error, 1)
			go func() { checked <- s.CheckLease(context.Background()) }()
			select {
			case err := <-checked:
				t.Fatal("lease check returned while the explicit stop was still cleaning up", err)
			case <-time.After(6 * leaseStallBound):
			}
			close(runtime.release)
			if err := <-checked; err != nil {
				t.Fatal("lease check after a completed explicit stop", err)
			}
			if r := <-stopped; r.Error != "" {
				t.Fatal("explicit stop failed", r.Error)
			}
			if runtime.stops.Load() != 1 {
				t.Fatal("cleanup ran more than once", runtime.stops.Load())
			}
		})
	}
}

// lockBefore decides ownership with one atomic transition: whichever of the
// helper (lock taken) and the caller (gave up) moves first wins, and the lock
// ends up held by the caller exactly when the call returns true. The earlier
// two-channel version could return false after the helper had already taken
// the lock, leaving it held by nobody for good.
func TestLockBeforeHandsOffAtomically(t *testing.T) {
	var mu sync.Mutex
	// Gave up while another holder keeps the lock: the helper must release it
	// once that holder lets go, so a later TryLock succeeds.
	mu.Lock()
	giveUp := make(chan time.Time, 1)
	giveUp <- time.Time{}
	if lockBefore(&mu, giveUp) {
		t.Fatal("acquired a lock another holder keeps")
	}
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for !mu.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("helper kept the lock after the caller gave up")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Unlock()
	// The boundary: the give-up signal and a free lock race. Whatever the
	// outcome, true means the caller holds it and false means it is free.
	for i := 0; i < 2000; i++ {
		fired := make(chan time.Time, 1)
		fired <- time.Time{}
		if lockBefore(&mu, fired) {
			if mu.TryLock() {
				t.Fatal("returned true without holding the lock")
			}
			mu.Unlock()
			continue
		}
		deadline := time.Now().Add(5 * time.Second)
		for !mu.TryLock() {
			if time.Now().After(deadline) {
				t.Fatal("returned false and left the lock held")
			}
			time.Sleep(50 * time.Microsecond)
		}
		mu.Unlock()
	}
}

type stuckRuntime struct {
	runtimeFake
	entered chan struct{}
	release chan struct{}
}

func (r *stuckRuntime) Apply(ctx context.Context, v policy.Revision) (policy.Applied, error) {
	close(r.entered)
	<-r.release
	return r.runtimeFake.Apply(ctx, v)
}

// Spec §2: a lapsed lease stops forwarding. A command stuck inside the engine
// (a durable write that never returns) holds the mutation lock; the expiry
// must not wait on it forever but report the stall, so the host fails open.
// On main this call blocks until the command returns.
func TestExpiredLeaseDoesNotWaitOnAStuckCommand(t *testing.T) {
	old := leaseStallBound
	leaseStallBound = 100 * time.Millisecond
	t.Cleanup(func() { leaseStallBound = old })
	table := flows.New(flows.Defaults(), nil)
	runtime := &stuckRuntime{runtimeFake: runtimeFake{table: table}, entered: make(chan struct{}), release: make(chan struct{})}
	s := New(runtime, table, nil)
	if r := s.Handle(context.Background(), Request{ID: "attach", Method: "attach", Instance: s.Instance}); r.Error != "" {
		t.Fatal(r.Error)
	}
	start := revision(1)
	if r := s.Handle(context.Background(), Request{ID: "start", Method: "start", Instance: s.Instance, Epoch: 1, Revision: &start}); r.Error != "" {
		t.Fatal(r.Error)
	}
	stuck := revision(2)
	go s.Handle(context.Background(), Request{ID: "apply", Method: "apply", Instance: s.Instance, Epoch: 1, Revision: &stuck})
	<-runtime.entered
	s.mu.Lock()
	expired := s.expires.Add(time.Nanosecond)
	s.now = func() time.Time { return expired }
	s.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- s.CheckLease(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseStalled) {
			t.Fatal("expiry with a stuck command must report the stall", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lease expiry waited on the stuck command")
	}
	if runtime.stops.Load() != 0 {
		t.Fatal("cleanup ran while the engine was still held")
	}
	// The stall is routed to its own hook, not to the cleanup-failure hook,
	// because a graceful cleanup would wait on the same lock.
	stalled := make(chan error, 1)
	s.OnLeaseStall = func(err error) { stalled <- err }
	s.OnCleanupFailure = func(err error) { t.Error("stall reported as a cleanup failure", err) }
	ctx, cancel := context.WithCancel(context.Background())
	go s.RunLease(ctx)
	select {
	case err := <-stalled:
		if !errors.Is(err, ErrLeaseStalled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunLease never reported the stall")
	}
	cancel()
	close(runtime.release)
	// Once the command returns, the ordinary lapse cleanup proceeds.
	if err := s.CheckLease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.stops.Load() != 1 {
		t.Fatal("cleanup did not run after the command released the engine")
	}
}
