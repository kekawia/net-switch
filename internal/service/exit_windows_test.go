package service

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// stopService runs h until it is ready, sends request and returns how Execute
// ended, or reports a stop that is still running after wait.
func stopService(t *testing.T, h *handler, wait time.Duration, request ...svc.Cmd) (bool, uint32, bool) {
	t.Helper()
	requests := make(chan svc.ChangeRequest, 1)
	updates := make(chan svc.Status, 64)
	type exit struct {
		specific bool
		code     uint32
	}
	done := make(chan exit, 1)
	go func() { specific, code := h.Execute(nil, requests, updates); done <- exit{specific, code} }()
	for s := range updates {
		if s.State == svc.Running {
			break
		}
	}
	cmd := svc.Stop
	if len(request) != 0 {
		cmd = request[0]
	}
	requests <- svc.ChangeRequest{Cmd: cmd}
	select {
	case e := <-done:
		return e.specific, e.code, true
	case <-time.After(wait):
		return false, 0, false
	}
}

// Twice on 2026-11-27 Control never returned from a stop and the service
// manager waited 90 minutes; Execute kept reporting progress every second.
func TestStopThatNeverFinishesEndsAtItsBoundWithItsGoroutines(t *testing.T) {
	previous := stopOverrun
	stopOverrun = 300 * time.Millisecond
	t.Cleanup(func() { stopOverrun = previous })
	var dump atomic.Pointer[string]
	SetStopOverrunReport(func(message string) { dump.Store(&message) })
	t.Cleanup(func() { stopOverrunReport.Store(nil) })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := &handler{name: "test", run: func(_ context.Context, ready func()) error {
		ready()
		<-release // waits without a bound and ignores the stop
		return nil
	}}
	specific, code, stopped := stopService(t, h, 5*time.Second)
	if !stopped {
		t.Fatal("a program that never returns still held the stop open")
	}
	// Both services restart on a failed exit; an update or uninstall that
	// stopped one must not have it started again.
	if specific || code != 0 || h.err == nil {
		t.Fatalf("an overrun stop ended as specific=%t code=%d err=%v, want stopped for good", specific, code, h.err)
	}
	message := dump.Load()
	if message == nil || !strings.Contains(*message, "service stop overran") || !strings.Contains(*message, "TestStopThatNeverFinishesEndsAtItsBoundWithItsGoroutines") {
		t.Fatal("the program's log did not get the stuck goroutine's stack")
	}
	// A requested restart that overran still fails, so it is restarted.
	h = &handler{name: "test", run: h.run}
	if specific, code, stopped := stopService(t, h, 5*time.Second, svc.Cmd(128)); !stopped || !specific || code != 1 {
		t.Fatalf("an overrun restart ended as stopped=%t specific=%t code=%d, want a failed exit", stopped, specific, code)
	}
	// A program whose own log is stuck still lets the stop end.
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	SetStopOverrunReport(func(string) { <-stuck })
	h = &handler{name: "test", run: h.run}
	if _, _, stopped := stopService(t, h, 10*time.Second); !stopped {
		t.Fatal("a stuck log kept the stop open")
	}
}

func TestStopWithinItsBoundKeepsTheProgramsOutcome(t *testing.T) {
	previous := stopOverrun
	stopOverrun = 2 * time.Second
	t.Cleanup(func() { stopOverrun = previous })
	called := atomic.Bool{}
	SetStopOverrunReport(func(string) { called.Store(true) })
	t.Cleanup(func() { stopOverrunReport.Store(nil) })
	h := &handler{name: "test", run: func(ctx context.Context, ready func()) error {
		ready()
		<-ctx.Done()
		time.Sleep(200 * time.Millisecond) // a normal, bounded shutdown
		return nil
	}}
	specific, code, stopped := stopService(t, h, 5*time.Second)
	if !stopped || specific || code != 0 || h.err != nil || called.Load() {
		t.Fatalf("a bounded stop ended as stopped=%t specific=%t code=%d err=%v overrun=%t", stopped, specific, code, h.err, called.Load())
	}
}

func TestSCMRetainsOnlyDirectCompletedExitOutcome(t *testing.T) {
	for _, failure := range []error{completedExit(3), errors.Join(completedExit(3), errors.New("late close")), nil} {
		h := &handler{run: func(context.Context, func()) error { return failure }}
		specific, code := h.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 8))
		if code != uint32(ExitCode(failure)) || specific != (failure != nil) {
			t.Fatalf("SCM outcome specific=%t code=%d for %v", specific, code, failure)
		}
	}
}
