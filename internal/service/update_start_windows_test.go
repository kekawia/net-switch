package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// Models another client's already-starting instance, which exits before the
// new image can start. No native service, token, registry or process is used.
type pendingServiceStart struct {
	pending, starts int
	exitCode        uint32
	observed        svc.State
	started         bool
}

func (s *pendingServiceStart) Query() (svc.Status, error) {
	state := svc.Stopped
	if s.started {
		state = svc.Running
	} else if s.pending > 0 {
		s.pending--
		state = svc.StartPending
	}
	s.observed = state
	return svc.Status{State: state, Win32ExitCode: s.exitCode}, nil
}

func (s *pendingServiceStart) Start(...string) error {
	s.starts++
	if s.observed != svc.Stopped {
		return windows.ERROR_SERVICE_ALREADY_RUNNING
	}
	s.started = true
	return nil
}

func TestUpdateStartWaitsForPriorGuardBeforeStartingNewImage(t *testing.T) {
	s := &pendingServiceStart{pending: 2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := startServiceHandle(ctx, Control, s, true); err != nil || !s.started || s.starts != 1 {
		t.Fatalf("new image was not started after the old guard exited: %+v, %v", s, err)
	}
}

func TestUpdateStartDoesNotHideARealStartupFailure(t *testing.T) {
	s := &pendingServiceStart{pending: 2, exitCode: 17}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := startServiceHandle(ctx, Control, s, true)
	if err == nil || !strings.Contains(err.Error(), "exit 17") || s.starts != 0 {
		t.Fatalf("failed startup was retried or hidden: %+v, %v", s, err)
	}
}

func TestOrdinaryStartPreservesExistingStartupFailureBehavior(t *testing.T) {
	s := &pendingServiceStart{pending: 2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := startServiceHandle(ctx, Control, s, false)
	if err == nil || !strings.Contains(err.Error(), "stopped during startup") || s.started {
		t.Fatalf("ordinary service start behavior changed: %+v, %v", s, err)
	}
}
