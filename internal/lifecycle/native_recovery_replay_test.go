package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Start the shared native fixture with a durable desired revision.
func newRecoveryReplay(t *testing.T) *nativeFixture {
	t.Helper()
	f := newNativeFixture(t, nativeProber{})
	r := f.remote
	ctx := r.ctx
	rev := testRevision(1)
	r.Restore(&rev)
	if err := r.Start(ctx, rev.Policy); err != nil {
		t.Fatal(err)
	}
	if s := r.Snapshot(); s.Status != "on" || s.Instance != f.server.Instance || s.AppliedRevision != 1 {
		t.Fatalf("replay must begin with a loaded native instance: %+v", s)
	}
	return f
}

// predicate runs under Remote's state lock, so the test waits for publication,
// not merely for the server to have produced an answer.
func awaitRecovery(t *testing.T, r *Remote, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		ready := predicate()
		r.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("native recovery did not settle", r.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *nativeFixture) interrupted() {
	f.remote.mu.Lock()
	rpc := f.remote.rpc
	f.remote.mu.Unlock()
	f.remote.disconnect(rpc, errors.New("replay transport interrupted"))
}

func TestNativeRecoveryReplayReattach(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	original := r.dial
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r.dial = func(ctx context.Context, endpoint localipc.Endpoint) (*localipc.Conn, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return original(ctx, endpoint)
	}
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	// Closing the byte transport lets RPC and Remote's renew loop detect loss.
	rpc.conn.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no reattach attempt")
	}
	if s := r.Snapshot(); s.Status != "starting" || s.Instance != f.server.Instance || s.FailureID != "" || s.Error != nil {
		t.Fatal("held reconnect changed failure identity", s)
	}
	once.Do(func() { close(release) })
	awaitRecovery(t, r, func() bool {
		if r.snapshot.FailureID != "" || r.snapshot.Error != nil {
			t.Error("live native instance acquired a failure during reconnect")
		}
		return !r.recovering && r.snapshot.Status == "on" && f.hasLog("reattached to engine")
	})
	r.mu.Lock()
	epoch := r.epoch
	r.mu.Unlock()
	if s := r.Snapshot(); epoch != 2 || s.Instance != f.server.Instance || s.AppliedRevision != 1 || s.AppliedHash != testRevision(1).Hash || s.FailureID != "" || s.Error != nil {
		t.Fatal("native reattach lost revision or counted failure", epoch, s)
	}
	if !f.hasLog("engine transport interrupted") || !f.hasLog("reattached to engine") {
		t.Fatal("missing recovery diagnostics")
	}
	if err := r.call(r.ctx, "renew", nil, "", nil); err != nil {
		t.Fatal("reattached epoch cannot renew", err)
	}
}

func TestNativeRecoveryReplayStaleServiceQuery(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	original := r.dial
	var refusing atomic.Bool
	r.dial = func(ctx context.Context, endpoint localipc.Endpoint) (*localipc.Conn, error) {
		if refusing.Load() {
			return nil, errors.New("old transport gone")
		}
		return original(ctx, endpoint)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r.queryService = func(string) (service.Status, error) {
		close(entered)
		<-release
		return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 1}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "failure"}, nil
	}
	refusing.Store(true)
	f.interrupted()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old query not reached")
	}
	refusing.Store(false)
	if err := r.Attach(r.ctx, false); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	awaitRecovery(t, r, func() bool { return !r.recovering })
	if s := r.Snapshot(); s.Status != "on" || s.Instance != f.server.Instance || s.FailureID != "" || s.Error != nil {
		t.Fatal("stale stopped query failed new attachment", s)
	}
}

func TestNativeRecoveryReplayFailureIdentity(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	r.failInstance(errors.New("observed instance failure"))
	id := r.Snapshot().FailureID
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) { return nil, errors.New("gone") }
	r.queryService = func(string) (service.Status, error) {
		return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true, ExitCode: 1}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "failure"}, nil
	}
	f.interrupted()
	awaitRecovery(t, r, func() bool { return !r.recovering })
	if s := r.Snapshot(); id != f.server.Instance || s.FailureID != id || s.Status != "error" {
		t.Fatal("one failed native instance produced multiple identities", id, s)
	}
	if s := r.Snapshot(); s.Error == nil || !strings.Contains(*s.Error, "engine instance exited") || !strings.Contains(*s.Error, "replay transport interrupted") {
		t.Fatal("second exit classification did not publish the interruption cause", s)
	}
}

func TestNativeRecoveryReplayForgetLane(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	// Hold the RPC request mutex: any IPC would block, including a call that
	// uses the existing connection instead of dialing again.
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	rpc.mu.Lock()
	done := make(chan struct{})
	go func() { r.ForgetLane("b2"); close(done) }()
	select {
	case <-done:
		rpc.mu.Unlock()
	case <-time.After(time.Second):
		rpc.mu.Unlock()
		<-done
		t.Fatal("native ForgetLane performed IPC")
	}
	if s := r.Snapshot(); s.Policy.Lanes["b2"] != "b2" || s.AppliedRevision != 1 {
		t.Fatal("native revision was partially invalidated", s)
	}
}

func TestNativeRecoveryReplayAcknowledgedStop(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	var waited, forced bool
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	r.waitStopped = func(ctx context.Context, name string) error {
		waited = true
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Second || name != service.Engine {
			t.Error("unbounded or wrong service wait")
		}
		if state, _ := f.runtime.LiveState(); state != "off" {
			t.Error("wait preceded real native stop acknowledgement")
		}
		if f.runtime.table.Applied() != nil {
			t.Error("acknowledged native stop retained loaded policy")
		}
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	r.forceStop = func(ctx context.Context, name string) error {
		forced = true
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second || name != service.Engine {
			t.Error("unbounded or wrong forced cleanup")
		}
		if r.Snapshot().Status == "off" {
			t.Error("off published before forced cleanup")
		}
		return nil
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !waited || !forced || r.Snapshot().Status != "off" || !f.hasLog("terminating its service to fail open") {
		t.Fatal("bounded stop did not complete with diagnostics")
	}
}
func TestNativeRecoveryReplaySevenLeaseExits(t *testing.T) {
	f := newNativeFixture(t, nativeProber{})
	r := f.remote
	dial := r.dial
	rev := testRevision(1)
	r.Restore(&rev)
	for cycle := range 7 {
		t.Run(string(rune('1'+cycle)), func(t *testing.T) {
			// Each exited instance is replaced, but Remote's accumulated state
			// survives all seven off/start transitions.
			f.dialMu.Lock()
			table := flows.New(flows.Defaults(), nil)
			f.runtime = &nativeRuntime{table: table, started: time.Now()}
			f.server = protocol.New(f.runtime, table, nativeProber{})
			f.dialMu.Unlock()
			r.dial = dial
			r.queryService = func(string) (service.Status, error) { return service.Status{Running: true, PID: 4242}, nil }
			if err := r.Start(r.ctx, rev.Policy); err != nil {
				t.Fatal(err)
			}
			if s := r.Snapshot(); s.Status != "on" || s.Instance != f.server.Instance || s.AppliedRevision != 1 {
				t.Fatal("cycle did not start a loaded replacement", s)
			}
			r.mu.Lock()
			attempt := r.attempt
			r.mu.Unlock()
			if attempt != uint64(cycle+1) {
				t.Fatal("Remote state reset between cycles", attempt)
			}
			r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
				return nil, errors.New("lease exited")
			}
			r.queryService = func(string) (service.Status, error) {
				return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}, nil
			}
			r.outcome = func(instance string) (host.Outcome, error) {
				if instance != f.server.Instance {
					t.Error("outcome requested for wrong instance")
				}
				return host.Outcome{Instance: instance, State: "complete", Reason: "lease-expired"}, nil
			}
			f.interrupted()
			awaitRecovery(t, r, func() bool { return !r.recovering })
			if s := r.Snapshot(); s.Status != "off" || s.FailureID != "" || s.Error != nil {
				t.Fatal("lease exit consumed failure identity", s)
			}
		})
	}
}

func TestNativeRecoveryReplayFailedForcedStop(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	waitErr, forceErr := errors.New("service did not stop"), errors.New("cleanup refused")
	var stopped atomic.Bool
	queried := make(chan struct{}, 1)
	r.queryService = func(string) (service.Status, error) {
		select {
		case queried <- struct{}{}:
		default:
		}
		if stopped.Load() {
			return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}, nil
		}
		return service.Status{Running: true, PID: 4242}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "stop"}, nil
	}
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		return nil, errors.New("host is stopping")
	}
	r.waitStopped = func(context.Context, string) error { return waitErr }
	r.forceStop = func(context.Context, string) error { return forceErr }
	r.mu.Lock()
	rpc := r.rpc
	r.mu.Unlock()
	err := r.Stop(r.ctx)
	if !errors.Is(err, waitErr) || !errors.Is(err, forceErr) || !strings.Contains(err.Error(), "forced engine cleanup failed") {
		t.Fatal("stop did not preserve both failures", err)
	}
	r.mu.Lock()
	stopping := r.stopping
	r.mu.Unlock()
	if s := r.Snapshot(); s.Status == "off" || stopping {
		t.Fatal("failed forced cleanup reported completion or left stopping latched", stopping, s)
	}
	rpc.conn.Close()
	select {
	case <-queried:
	case <-time.After(5 * time.Second):
		t.Fatal("transport loss did not resume recovery")
	}
	if s := r.Snapshot(); s.Status != "stopping" || s.FailureID != "" {
		t.Fatal("acknowledged stop was reported as starting or failed", s)
	}
	stopped.Store(true)
	awaitRecovery(t, r, func() bool { return !r.recovering && r.snapshot.Status == "off" })
	if s := r.Snapshot(); s.FailureID != "" || s.Error != nil {
		t.Fatal("completed stop consumed crash budget", s)
	}
}

func TestNativeRecoveryReplayOverlappingStops(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	r.waitStopped = func(context.Context, string) error { return errors.New("service wait failed") }
	first, second := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	r.forceStop = func(context.Context, string) error {
		if calls.Add(1) == 1 {
			close(first)
			<-release
		} else {
			close(second)
		}
		return errors.New("forced cleanup failed")
	}
	var aErr, bErr error
	var joined sync.WaitGroup
	joined.Add(2)
	t.Cleanup(func() { once.Do(func() { close(release) }); joined.Wait() })
	go func() { defer joined.Done(); aErr = r.Stop(r.ctx) }()
	<-first
	started := make(chan struct{})
	go func() { defer joined.Done(); close(started); bErr = r.Stop(r.ctx) }()
	<-started
	select {
	case <-second:
		t.Error("Stop B entered forced cleanup while Stop A still owned stop state")
	case <-time.After(100 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	joined.Wait()
	if calls.Load() != 1 || aErr == nil || bErr != aErr {
		t.Fatal("overlapping callers did not share one Stop result", calls.Load(), aErr, bErr)
	}
}

func TestNativeRecoveryReplayTransportLostDuringStop(t *testing.T) {
	for _, reason := range []string{"stop", "failure"} {
		t.Run(reason, func(t *testing.T) {
			f := newRecoveryReplay(t)
			r := f.remote
			queried := make(chan struct{}, 1)
			r.queryService = func(string) (service.Status, error) {
				select {
				case queried <- struct{}{}:
				default:
				}
				return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}, nil
			}
			r.outcome = func(instance string) (host.Outcome, error) {
				return host.Outcome{Instance: instance, State: "complete", Reason: reason}, nil
			}
			r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
				return nil, errors.New("host no longer answers")
			}
			r.waitStopped = func(ctx context.Context, _ string) error {
				r.mu.Lock()
				rpc := r.rpc
				r.mu.Unlock()
				rpc.conn.Close()
				select {
				case <-rpc.Done():
				case <-ctx.Done():
					return ctx.Err()
				}
				// Observe renew's swallowed disconnect before allowing Stop to
				// clear its flag. This forces the early-loss ordering.
				awaitRecovery(t, r, func() bool { return f.hasLog("transport interrupted during stop; deferring recovery") })
				return errors.New("service wait failed after transport loss")
			}
			r.forceStop = func(context.Context, string) error { return errors.New("forced cleanup failed") }
			if err := r.Stop(r.ctx); err == nil {
				t.Fatal("failed stop returned success")
			}
			select {
			case <-queried:
			case <-time.After(time.Second):
				t.Fatal("swallowed transport loss never resumed recovery")
			}
			awaitRecovery(t, r, func() bool { return !r.recovering })
			s := r.Snapshot()
			if reason == "stop" {
				if s.Status != "off" || s.FailureID != "" {
					t.Fatal("clean stop did not converge to off", s)
				}
			} else if s.Status != "error" || s.FailureID != f.server.Instance {
				t.Fatal("crash outcome was not counted", s)
			}
		})
	}
}

func TestNativeRecoveryReplayStaleQueryIsPaced(t *testing.T) {
	f := newRecoveryReplay(t)
	r := f.remote
	r.dial = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		return nil, errors.New("unavailable")
	}
	queries := make(chan time.Time, 2)
	r.queryService = func(string) (service.Status, error) {
		// A concurrent failed start advances attempt while the service query
		// is in flight, making this classification stale on every iteration.
		r.mu.Lock()
		r.attempt++
		r.mu.Unlock()
		select {
		case queries <- time.Now():
		default:
		}
		return service.Status{Stopped: true, Cleanup: "complete", ExitKnown: true}, nil
	}
	r.outcome = func(instance string) (host.Outcome, error) {
		return host.Outcome{Instance: instance, State: "complete", Reason: "stop"}, nil
	}
	f.interrupted()
	read := func() time.Time {
		select {
		case at := <-queries:
			return at
		case <-time.After(5 * time.Second):
			t.Fatal("recovery did not query service")
			return time.Time{}
		}
	}
	first, second := read(), read()
	if elapsed := second.Sub(first); elapsed < 900*time.Millisecond {
		t.Fatalf("stale recovery spun without pause: two queries in %s", elapsed)
	}
}
