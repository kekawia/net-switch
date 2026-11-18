package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// The caller owns update.lock. The new process cannot change the journal until
// its immutable PID/creation identity has been saved and that lock released.
func startJournalUpdater(j *updateJournal) error {
	p, err := startUpdateProcess(j.runner(), []string{"update", "--apply", "--data", j.Data, "--operation", j.Status.Operation}, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p.Process)
	var created, exited, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(p.Process, &created, &exited, &kernel, &user); err == nil {
		j.RunnerPID, j.RunnerCreated = p.ProcessId, created.Nanoseconds()
		err = saveUpdateJournal(j)
	}
	if err != nil {
		_ = windows.TerminateProcess(p.Process, 1)
		_, _ = windows.WaitForSingleObject(p.Process, 10000)
	}
	return err
}

func updateRunnerAlive(j updateJournal) (bool, error) {
	if j.RunnerPID == 0 || j.RunnerCreated == 0 {
		return false, nil
	}
	p, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, j.RunnerPID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(p)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p, &created, &exited, &kernel, &user); err != nil {
		return false, err
	}
	if created.Nanoseconds() != j.RunnerCreated {
		return false, nil
	}
	state, err := windows.WaitForSingleObject(p, 0)
	return state == uint32(windows.WAIT_TIMEOUT), err
}

func (u *controlUpdater) watchInterruptedUpdate() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			recoverPendingUpdate(u.ctx, u.config.Data, u.log, true)
		}
	}
}

// The desktop may activate Control while the updater is stopping services.
// Start recovery if needed, then exit cleanly instead of reporting a running
// service which waits for the updater: that would recreate the very service
// the updater is waiting to stop. The installer starts Control explicitly once
// its matching health transaction is ready; no data writer starts before it.
func deferControlForUpdate(ctx context.Context, data string, log func(string)) (bool, error) {
	resolved, err := ResolveStore(data)
	if err != nil {
		return false, err
	}
	recoverPendingUpdate(ctx, resolved, log, false)
	j, err := readUpdateJournal(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !j.Captured || completedUpdate(j.Status.Phase) {
		return false, nil
	}
	if j.Status.Phase == "failed" {
		return false, errors.New("update recovery failed; installation repair is required")
	}
	return !updateHealthReady(j), nil
}

func updateHealthReady(j updateJournal) bool {
	version := j.Status.Version
	switch j.Status.Phase {
	case "applying", "checking":
	case "rolling-back":
		version = j.Status.PreviousVersion
	default:
		return false
	}
	var migration MigrationJournal
	if Read(filepath.Join(j.Data, "migration-journal.json"), &migration) != nil ||
		migration.UpdateOperation != j.Status.Operation || migration.Version != version ||
		(migration.Phase != "installed" && migration.Phase != "committed") {
		return false
	}
	config, err := LoadConfig(j.Data)
	if err != nil || !strings.EqualFold(config.Directory, filepath.Join(j.AppDir, "app-"+version)) {
		return false
	}
	executable, err := os.Executable()
	return err == nil && strings.EqualFold(filepath.Dir(executable), config.Directory)
}
