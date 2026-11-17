package updates

import (
	"context"
	"errors"
	"testing"
)

type transactionFixture struct {
	status                 Status
	data, binary, snapshot string
	installs, restores     int
	failure, crash         string
	code                   uint32
}

func newTransactionFixture() *transactionFixture {
	return &transactionFixture{status: Status{Operation: "test", Phase: "ready", Version: "1.1.0", PreviousVersion: "1.0.0"}, data: "original settings", binary: "1.0.0"}
}

func (f *transactionFixture) ops() TransactionOps {
	return TransactionOps{
		Save: func(s Status) error {
			f.status = s
			if f.crash == s.Phase {
				panic("power loss")
			}
			return nil
		},
		Prepare: func(context.Context) error { f.snapshot = f.data; return nil },
		Install: func(context.Context) (uint32, error) {
			f.installs++
			f.binary, f.data = "1.1.0", "new incompatible data"
			if f.failure == "install" {
				return 0, errors.New("installer failure")
			}
			return f.code, nil
		},
		Health: func(context.Context) error {
			if f.failure == "health" {
				return errors.New("health failure")
			}
			return nil
		},
		Keep: func(context.Context) error {
			if f.failure == "keep" {
				return errors.New("disk full")
			}
			return nil
		},
		Rollback: func(ctx context.Context) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if f.failure == "rollback" {
				return errors.New("old installer unavailable")
			}
			f.restores++
			f.binary = "1.0.0"
			if f.snapshot != "" {
				f.data = f.snapshot
			}
			return nil
		},
	}
}

func TestUpdateTransactionCommitsOrRestoresBinariesAndData(t *testing.T) {
	for _, failure := range []string{"", "install", "health", "keep"} {
		t.Run(failure, func(t *testing.T) {
			f := newTransactionFixture()
			f.failure = failure
			status, err := RunTransaction(context.Background(), f.status, f.ops())
			if failure == "" {
				if err != nil || status.Phase != "complete" || f.binary != "1.1.0" {
					t.Fatal(status, err, f)
				}
			} else if err == nil || status.Phase != "rolled-back" || f.binary != "1.0.0" || f.data != "original settings" || f.restores != 1 {
				t.Fatal(status, err, f)
			}
			_, _ = RunTransaction(context.Background(), f.status, f.ops())
			if f.installs != 1 {
				t.Fatal("terminal transaction installed twice")
			}
		})
	}
	f := newTransactionFixture()
	f.code = 3010
	status, err := RunTransaction(context.Background(), f.status, f.ops())
	if err != nil || status.Phase != "reboot-required" || !status.RebootRequired {
		t.Fatal(status, err)
	}
}

func TestUpdateTransactionRecoversEveryDurableBoundary(t *testing.T) {
	for _, point := range []string{"preparing", "snapshotted", "applying", "checking", "complete"} {
		t.Run(point, func(t *testing.T) {
			f := newTransactionFixture()
			f.crash = point
			func() {
				defer func() {
					if recover() != "power loss" {
						t.Fatal("fault did not fire")
					}
				}()
				_, _ = RunTransaction(context.Background(), f.status, f.ops())
			}()
			f.crash = ""
			status, err := RunTransaction(context.Background(), f.status, f.ops())
			if point == "complete" {
				if err != nil || f.binary != "1.1.0" || f.restores != 0 {
					t.Fatal(status, err, f)
				}
			} else if err == nil || status.Phase != "rolled-back" || f.binary != "1.0.0" || f.data != "original settings" {
				t.Fatal(status, err, f)
			}
		})
	}
}

func TestUpdateRollbackFailureIsNeverReportedAsRestored(t *testing.T) {
	f := newTransactionFixture()
	f.code = 5
	f.failure = "rollback"
	status, err := RunTransaction(context.Background(), f.status, f.ops())
	if err == nil || status.Phase != "failed" || f.binary != "1.1.0" || f.restores != 0 {
		t.Fatal("false rollback success", status, err)
	}
}

func TestUpdateNeverRestoresDataWhileAnInstallerChildIsAlive(t *testing.T) {
	f := newTransactionFixture()
	ops := f.ops()
	ops.Install = func(context.Context) (uint32, error) { return 0, ErrInstallerStillRunning }
	status, err := RunTransaction(context.Background(), f.status, ops)
	if !errors.Is(err, ErrInstallerStillRunning) || status.Phase != "failed" || f.restores != 0 {
		t.Fatal("unsafe concurrent rollback", status, err)
	}
}
