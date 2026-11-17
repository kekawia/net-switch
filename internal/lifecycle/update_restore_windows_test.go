package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	win "github.com/kekawia/net-switch/internal/platform/windows"
)

func TestHostedUndoPreparationPrecedesUpdateLock(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("machine-store certification only runs on disposable hosted Windows")
	}
	proofParent := filepath.Clean(os.Getenv("ProgramData"))
	if !filepath.IsAbs(proofParent) {
		t.Fatal("hosted ProgramData path is not absolute")
	}
	newStore := func() (string, string) {
		t.Helper()
		requested := filepath.Join(proofParent, "NetSwitch-update-undo-proof-"+randomID()[:16])
		if !strings.EqualFold(filepath.Dir(requested), proofParent) {
			t.Fatal("proof store escaped its parent")
		}
		data, err := PrepareStore(requested)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := CleanupMachineDataCommand(requested); err != nil {
				t.Error(err)
			}
		})
		return requested, data
	}
	requested, data := newStore()
	before, err := os.Stat(data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := (Lock{Data: data, Name: "update"}).Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prepareErr := win.PrepareMachineUninstall(requested, func(string) {})
	if err := release(); err != nil {
		t.Fatal(err)
	}
	// Protection may report either a sharing failure or the subsequent refused
	// quarantine rename. The contract is refusal without replacing the live tree.
	if prepareErr == nil {
		t.Fatal("exclusive preparation accepted a held update lock")
	}
	after, err := os.Stat(data)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("held live folder was replaced", err)
	}
	// The deliberately failed protection attempt can leave a certified stage.
	// Test the corrected CLI order on a fresh store with an existing closed lock.
	fresh, freshData := newStore()
	freshCtx, stopFresh := context.WithTimeout(context.Background(), time.Second)
	defer stopFresh()
	release, err = (Lock{Data: freshData, Name: "update"}).Acquire(freshCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := Ctl([]string{"restore-windows", "--data", fresh}); err != nil {
		t.Fatal("restore failed with correct preparation/lock ordering", err)
	}
}
