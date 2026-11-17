package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	win "github.com/kekawia/net-switch/internal/platform/windows"
	"golang.org/x/sys/windows"
)

func TestHostedUndoPreparationPrecedesUpdateLock(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("machine-store certification only runs on disposable hosted Windows")
	}
	proofParent := filepath.Clean(os.Getenv("ProgramData"))
	if !filepath.IsAbs(proofParent) {
		t.Fatal("hosted ProgramData path is not absolute")
	}
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
	if !errors.Is(prepareErr, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("expected exclusive protection to refuse the held update lock, got %v", prepareErr)
	}
	if err := Ctl([]string{"restore-windows", "--data", requested}); err != nil {
		t.Fatal("restore failed with correct preparation/lock ordering", err)
	}
}
