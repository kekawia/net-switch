package lifecycle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func TestStopWithoutSessionDoesNotRecover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewRemote(ctx, func(string) {})
	var queries, dials atomic.Int32
	r.queryService = func(string) (service.Status, error) {
		if queries.Add(1) == 1 {
			return service.Status{}, errors.New("SCM unavailable")
		}
		return service.Status{Stopped: true}, nil
	}
	r.forceStop = func(context.Context, string) error { return errors.New("SCM still unavailable") }
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no engine")
	}
	if err := r.Stop(ctx); err == nil {
		t.Fatal("SCM failures hidden")
	}
	r.mu.Lock()
	recovering := r.recovering
	r.mu.Unlock()
	if s := r.Snapshot(); recovering || s.Status != "off" || s.FailureID != "" || dials.Load() != 0 {
		t.Fatal("nonexistent engine entered recovery", recovering, s, dials.Load())
	}
}

func TestStopPanicReleasesFlight(t *testing.T) {
	r := NewRemote(context.Background(), func(string) {})
	r.queryService = func(string) (service.Status, error) { panic("query panic") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Stop swallowed panic")
			}
		}()
		_ = r.Stop(context.Background())
	}()
	r.stop.Lock()
	flight := r.stopFlight
	r.stop.Unlock()
	if flight != nil {
		t.Error("panic left a pending stop flight")
	}
	r.queryService = func(string) (service.Status, error) { return service.Status{Stopped: true}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := r.Stop(ctx); err != nil {
		t.Fatal("later Stop blocked after panic", err)
	}
}

type stopJoinContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *stopJoinContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestStopJoinerRetriesCanceledOwner(t *testing.T) {
	r := NewRemote(context.Background(), func(string) {})
	entered, release := make(chan struct{}), make(chan struct{})
	var queries atomic.Int32
	r.queryService = func(string) (service.Status, error) {
		if queries.Add(1) == 1 {
			close(entered)
			<-release
			return service.Status{}, context.Canceled
		}
		return service.Status{Stopped: true}, nil
	}
	r.forceStop = func(context.Context, string) error { return context.Canceled }
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) { return nil, context.Canceled }
	owner, joiner := make(chan error, 1), make(chan error, 1)
	go func() { owner <- r.Stop(context.Background()) }()
	<-entered
	ctx := &stopJoinContext{Context: context.Background(), entered: make(chan struct{})}
	go func() { joiner <- r.Stop(ctx) }()
	<-ctx.entered
	close(release)
	if err := <-owner; !errors.Is(err, context.Canceled) {
		t.Fatal("owner error", err)
	}
	if err := <-joiner; err != nil || queries.Load() != 2 {
		t.Fatal("live joiner did not retry once", err, queries.Load())
	}
}

func TestStopSuccessCannotOrphanReplacement(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	replacement := newNativeFixture(t, nativeProber{})
	r.waitStopped = func(context.Context, string) error {
		// A concurrent Start has discarded the old session and publishes a
		// replacement while the old service wait is completing.
		r.mu.Lock()
		r.rpc = nil
		r.mu.Unlock()
		r.dial = replacement.remote.dial
		if err := r.Start(r.ctx, testRevision(1).Policy); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if err := r.Stop(r.ctx); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	if s := r.Snapshot(); rpc == nil || s.Instance != replacement.server.Instance || s.Status != "on" {
		t.Fatal("old stop orphaned the replacement", s)
	}
	if err := r.call(r.ctx, "renew", nil, "", nil); err != nil {
		t.Fatal("replacement session unusable", err)
	}
}
