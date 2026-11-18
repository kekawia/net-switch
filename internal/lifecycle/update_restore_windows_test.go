package lifecycle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	win "github.com/kekawia/net-switch/internal/platform/windows"
	"github.com/kekawia/net-switch/internal/service"
	"github.com/kekawia/net-switch/internal/updates"
	"golang.org/x/sys/windows"
)

func newHostedUpdateStore(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("machine-store certification only runs on disposable hosted Windows")
	}
	proofParent := filepath.Clean(os.Getenv("ProgramData"))
	if !filepath.IsAbs(proofParent) {
		t.Fatal("hosted ProgramData path is not absolute")
	}
	requested := filepath.Join(proofParent, "NetSwitch-update-proof-"+randomID()[:16])
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

func TestHostedUndoPreparationPrecedesUpdateLock(t *testing.T) {
	requested, data := newHostedUpdateStore(t)
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
	fresh, freshData := newHostedUpdateStore(t)
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

func newHostedUpdateJournal(t *testing.T) updateJournal {
	t.Helper()
	_, data := newHostedUpdateStore(t)
	architecture, err := expectedBinaryArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var created, exited, kernel, cpu windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &cpu); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(t.TempDir(), "installation")
	j := updateJournal{
		Status: updates.Status{Operation: randomID(), Phase: "preparing", Version: "1.0.11", PreviousVersion: "1.0.10"},
		AppDir: appDir, Data: data, Architecture: architecture, Captured: true,
		Previous:          Config{Directory: filepath.Join(appDir, "app-1.0.10"), Data: data, Mode: "tun"},
		Owner:             Owner{User: user.User.Sid.String()},
		PreviousInstaller: keptInstaller{Version: "1.0.10", Architecture: architecture},
		RunnerPID:         uint32(os.Getpid()), RunnerCreated: created.Nanoseconds(),
		ServicePaths: map[string]string{},
	}
	for name, file := range map[string]string{service.Control: "netswitch.exe", service.Engine: "netswitch-engine.exe"} {
		j.ServicePaths[name] = windows.ComposeCommandLine([]string{filepath.Join(j.Previous.Directory, file), "service", "--data", data})
	}
	return j
}

func TestHostedPendingUpdateStartupExitsBeforeRecoveryWait(t *testing.T) {
	j := newHostedUpdateJournal(t)
	data := j.Data
	if err := saveUpdateJournal(&j); err != nil {
		t.Fatal(err)
	}
	// The real test process is the live updater identity. No service or child
	// is started here. The old startup guard waited until this context expired,
	// keeping SCM Running while that updater waited for it to stop.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deferred, err := deferControlForUpdate(ctx, data, func(message string) { t.Log(message) })
	if err != nil || !deferred || ctx.Err() != nil {
		t.Fatalf("pending startup must exit without waiting for recovery: deferred=%v err=%v context=%v", deferred, err, ctx.Err())
	}
	after, err := readUpdateJournal(data)
	if err != nil || after.RecoveryAttempts != 0 || after.Status.Phase != j.Status.Phase {
		t.Fatalf("startup changed the live updater's transaction: %+v, %v", after, err)
	}
}

func TestHostedUpdateSnapshotRestoresChangedDataAndAbsence(t *testing.T) {
	j := newHostedUpdateJournal(t)
	write := func(path string, value any) {
		t.Helper()
		if err := Save(path, value); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	settingsPath := filepath.Join(j.Data, "settings.json")
	journalPath := filepath.Join(j.Data, "control-journal.json")
	enginePath := filepath.Join(j.Data, "engine-state.json")
	original := map[string]any{"lines": []any{map[string]any{"id": "aa11", "label": "Before update"}}, "appLines": map[string]any{`C:\Apps\before.exe`: "aa11"}}
	write(settingsPath, original)
	write(journalPath, map[string]any{"settings": original, "wanted": false, "revision": 42})
	write(enginePath, map[string]any{"instance": "before"})
	before := map[string][]byte{}
	for _, path := range []string{settingsPath, settingsPath + ".bak", journalPath, journalPath + ".bak"} {
		before[path] = read(path)
	}
	if err := captureUpdateData(&j); err != nil {
		t.Fatal(err)
	}
	// Reload the durable manifest as a replacement updater would.
	var err error
	j, err = readUpdateJournal(j.Data)
	if err != nil {
		t.Fatal(err)
	}
	write(settingsPath, map[string]any{"lines": []any{}, "appLines": map[string]any{}})
	write(journalPath, map[string]any{"settings": map[string]any{}, "wanted": true, "revision": 99})
	created := filepath.Join(j.Data, "proxy-secrets.json")
	write(created, map[string]any{})
	write(enginePath, map[string]any{"instance": "after"})
	engineAfter := read(enginePath)
	if err := restoreUpdateData(j); err != nil {
		t.Fatal(err)
	}
	for path, want := range before {
		if !bytes.Equal(read(path), want) {
			t.Fatalf("modified state was not restored: %s", filepath.Base(path))
		}
	}
	for _, path := range []string{created, created + ".bak"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("recorded absence was not restored: %s, %v", filepath.Base(path), err)
		}
	}
	if !bytes.Equal(read(enginePath), engineAfter) {
		t.Fatal("rollback restored stale engine ownership")
	}
	// Corrupt a later snapshot entry: validation must finish before even the
	// earlier, valid settings snapshot can overwrite live data.
	write(settingsPath, map[string]any{"marker": "must remain untouched"})
	untouched := read(settingsPath)
	write(filepath.Join(j.snapshotDir(), "control-journal.json"), map[string]any{"corrupted": true})
	if err := restoreUpdateData(j); err == nil || !bytes.Equal(read(settingsPath), untouched) {
		t.Fatalf("bad later snapshot caused partial restoration: %v", err)
	}
	j.SnapshotComplete = false
	if err := restoreUpdateData(j); err != nil || !bytes.Equal(read(settingsPath), untouched) {
		t.Fatalf("incomplete snapshot was used for restoration: %v", err)
	}
	t.Log("UPDATE_SNAPSHOT_PROOF changed_files=4 absent_files=2 engine_identity_preserved=true corruption_refused_before_write=true incomplete_snapshot_ignored=true")
}
