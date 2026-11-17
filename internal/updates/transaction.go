package updates

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const rollbackTimeout = 10 * time.Minute

var ErrInstallerStillRunning = errors.New("installer processes have not stopped; automatic rollback is unsafe")

// TransactionOps owns platform effects. Every phase is persisted before the
// next effect; replay of an interrupted apply conservatively restores the
// locally kept version and its completed data snapshot.
type TransactionOps struct {
	Save     func(Status) error
	Prepare  func(context.Context) error
	Install  func(context.Context) (uint32, error)
	Health   func(context.Context) error
	Keep     func(context.Context) error
	Rollback func(context.Context) error
}

func RunTransaction(ctx context.Context, status Status, ops TransactionOps) (Status, error) {
	if ops.Save == nil || ops.Prepare == nil || ops.Install == nil || ops.Health == nil || ops.Keep == nil || ops.Rollback == nil {
		return status, errors.New("incomplete update transaction operations")
	}
	switch status.Phase {
	case "complete", "reboot-required", "rolled-back", "failed":
		return status, nil
	case "ready":
	case "preparing", "snapshotted", "applying", "checking", "rolling-back":
		return rollbackTransaction(status, ops, errors.New("the previous update was interrupted"))
	default:
		return status, fmt.Errorf("cannot apply update in phase %q", status.Phase)
	}
	phase := func(value string) error { status.Phase = value; return ops.Save(status) }
	if err := phase("preparing"); err != nil {
		return status, err
	}
	if err := ops.Prepare(ctx); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	if err := phase("snapshotted"); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	if err := phase("applying"); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	code, err := ops.Install(ctx)
	if errors.Is(err, ErrInstallerStillRunning) {
		status.Phase = "failed"
		status.Error = err.Error()
		return status, errors.Join(err, ops.Save(status))
	}
	if err != nil {
		return rollbackTransaction(status, ops, err)
	}
	if code != 0 && code != 3010 {
		return rollbackTransaction(status, ops, fmt.Errorf("installer exited with code %d", code))
	}
	status.RebootRequired = code == 3010
	if err := phase("checking"); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	if err := ops.Health(ctx); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	if err := ops.Keep(ctx); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	final := "complete"
	if status.RebootRequired {
		final = "reboot-required"
	}
	if err := phase(final); err != nil {
		return rollbackTransaction(status, ops, err)
	}
	return status, nil
}

func rollbackTransaction(status Status, ops TransactionOps, cause error) (Status, error) {
	status.Phase = "rolling-back"
	journalErr := ops.Save(status)
	// An expired install deadline must not cancel restoration of the old app.
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := ops.Rollback(ctx); err != nil {
		status.Phase = "failed"
		failure := errors.Join(cause, journalErr, fmt.Errorf("rollback failed: %w", err))
		status.Error = failure.Error()
		return status, errors.Join(failure, ops.Save(status))
	}
	status.Phase = "rolled-back"
	status.RebootRequired = false
	failure := errors.Join(cause, journalErr)
	status.Error = failure.Error()
	return status, errors.Join(failure, ops.Save(status))
}
