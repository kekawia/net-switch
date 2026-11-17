package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	assets "github.com/kekawia/net-switch"
	"github.com/kekawia/net-switch/internal/service"
	"github.com/kekawia/net-switch/internal/updates"
	"github.com/kekawia/net-switch/internal/wintrust"
)

type controlUpdater struct {
	ctx      context.Context
	config   Config
	log      func(string)
	mu       sync.Mutex
	progress *updates.Status
}

func newControlUpdater(ctx context.Context, config Config, log func(string)) updates.Backend {
	u := &controlUpdater{ctx: ctx, config: config, log: log}
	go u.watchInterruptedUpdate()
	return u
}

func (u *controlUpdater) publish(status *updates.Status) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.progress = nil
	if status != nil {
		copy := *status
		u.progress = &copy
	}
}

func (u *controlUpdater) Status() *updates.Status {
	u.mu.Lock()
	if u.progress != nil {
		copy := *u.progress
		u.mu.Unlock()
		return &copy
	}
	u.mu.Unlock()
	j, err := readUpdateJournal(u.config.Data)
	if err != nil || j.Dismissed || j.Status.Phase == "complete" {
		return nil
	}
	return &j.Status
}

func (u *controlUpdater) Dismiss(operation string) error {
	ctx, cancel := context.WithTimeout(u.ctx, time.Second)
	defer cancel()
	release, err := (Lock{Data: u.config.Data, Name: "update"}).Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	j, err := readUpdateJournal(u.config.Data)
	if err != nil {
		return err
	}
	if j.Status.Operation != operation || j.Status.Busy() {
		return errors.New("update changed or is still running")
	}
	j.Dismissed = true
	if err := saveUpdateJournal(&j); err != nil {
		return err
	}
	u.publish(nil)
	return nil
}

func (u *controlUpdater) Start(ctx context.Context, version string) error {
	if !Administrator() {
		return errors.New("staging an update requires an administrator")
	}
	if !updates.CanonicalVersion(version) {
		return errors.New("invalid update version")
	}
	if s := u.Status(); s != nil && s.Busy() {
		if s.Version == version {
			return nil
		}
		return errors.New("another update is already running")
	}
	lockCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	release, err := (Lock{Data: u.config.Data, Name: "update"}).Acquire(lockCtx)
	if err != nil {
		return err
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = release()
		}
	}()
	if j, err := readUpdateJournal(u.config.Data); err == nil && j.Status.Busy() {
		return errors.New("another update is already running")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	current := assets.AppVersion()
	if !updates.CanonicalVersion(current) || !updates.IsNewer(version, current) || !strings.EqualFold(filepath.Base(u.config.Directory), "app-"+current) {
		return errors.New("update requires the current versioned installation")
	}
	if err := service.CheckInstallation(u.config.Directory); err != nil {
		return err
	}
	appDir := filepath.Dir(u.config.Directory)
	marker, exists, err := readNoFollowMarker(filepath.Join(appDir, "current"))
	if err != nil || !exists {
		return errors.New("current installation marker is unavailable")
	}
	sub, err := ParseCurrentMarker(marker)
	if err != nil || sub != "app-"+current {
		return errors.New("current installation changed")
	}
	architecture, err := expectedBinaryArchitecture()
	if err != nil {
		return err
	}
	if err := ensureUpdateStore(appDir); err != nil {
		return err
	}
	previous, err := loadKeptInstaller(appDir, current, architecture)
	if err != nil {
		return fmt.Errorf("previous installer is not available for rollback: %w", err)
	}
	pruneUpdateArtifacts(appDir, u.config.Data, current, u.log)
	j := updateJournal{Status: updates.Status{Operation: randomID(), Phase: "downloading", Version: version, PreviousVersion: current},
		AppDir: appDir, Data: u.config.Data, Architecture: architecture, Previous: u.config, PreviousInstaller: previous}
	if err := wintrust.EnsurePrivateDirectory(j.stageDir()); err != nil {
		return err
	}
	if err := saveUpdateJournal(&j); err != nil {
		return err
	}
	u.publish(&j.Status)
	accepted = true
	go func() {
		defer release()
		u.download(&j)
	}()
	return nil
}

func (u *controlUpdater) fail(j *updateJournal, phase string, cause error) {
	j.Status.Phase, j.LastError = phase, cause.Error()
	j.Status.Error = cause.Error()
	u.log("update: " + cause.Error())
	// This path is only reached before a runner has been accepted. Keep the
	// error journal, but release partial download space immediately.
	for _, path := range []string{j.stageDir(), filepath.Dir(j.runner())} {
		if err := removeNoFollowTree(path); err != nil {
			u.log("failed update cleanup: " + err.Error())
		}
	}
	if err := saveUpdateJournal(j); err != nil {
		u.log("save update result: " + err.Error())
		u.publish(&j.Status)
	} else {
		u.publish(nil)
	}
}

func (u *controlUpdater) download(j *updateJournal) {
	ctx, cancel := context.WithTimeout(u.ctx, 20*time.Minute)
	defer cancel()
	client := updateClient(j.Data)
	check, stop := context.WithTimeout(ctx, 20*time.Second)
	offer, err := client.Check(check, j.Status.PreviousVersion, j.Architecture)
	stop()
	if err != nil {
		phase := "download-error"
		if errors.Is(err, updates.ErrSignatureCheck) {
			phase = "signature-error"
		}
		u.fail(j, phase, err)
		return
	}
	if offer == nil || offer.Version != j.Status.Version || offer.Bundle == nil {
		u.fail(j, "signature-error", errors.New("release changed before update started"))
		return
	}
	manifest, err := updates.VerifyBundle(updates.RootPublicKey, *offer.Bundle, j.Status.PreviousVersion, j.Architecture, time.Now())
	if err != nil {
		u.fail(j, "signature-error", err)
		return
	}
	j.Status.Size = manifest.Size
	if err := stageUpdateBundle(*j, *offer.Bundle); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	f, err := wintrust.OpenPrivateFile(j.installer(), true)
	if err != nil {
		u.fail(j, "download-error", err)
		return
	}
	err = client.Download(ctx, manifest, f, func(n int64) { j.Status.Downloaded = n; u.publish(&j.Status) })
	syncErr, closeErr := f.Sync(), f.Close()
	if err = errors.Join(err, syncErr, closeErr); err != nil {
		phase := "download-error"
		if errors.Is(err, updates.ErrInstallerIntegrity) {
			phase = "signature-error"
		}
		_ = removeNoFollowTree(j.stageDir())
		u.fail(j, phase, err)
		return
	}
	j.Status.Phase = "verifying"
	u.publish(&j.Status)
	if err := saveUpdateJournal(j); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	if _, err := verifyStagedUpdate(*j); err != nil {
		u.fail(j, "signature-error", err)
		return
	}
	runnerDir := filepath.Dir(j.runner())
	if err := wintrust.EnsurePrivateDirectory(runnerDir); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	if err := copyPrivateUpdateFile(filepath.Join(j.Previous.Directory, "netswitchctl.exe"), j.runner()); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	j.RunnerSHA256, err = hashNoFollowRegularFile(j.runner())
	if err != nil {
		u.fail(j, "download-error", err)
		return
	}
	j.Status.Phase = "ready"
	if err := saveUpdateJournal(j); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	if err := startJournalUpdater(j); err != nil {
		u.fail(j, "download-error", err)
		return
	}
	u.publish(nil)
}

func verifyStagedUpdate(j updateJournal) (updates.Manifest, error) {
	bundle, err := readUpdateBundle(j)
	if err != nil {
		return updates.Manifest{}, err
	}
	manifest, err := updates.VerifyBundle(updates.RootPublicKey, bundle, j.Status.PreviousVersion, j.Architecture, time.Now())
	if err != nil {
		return manifest, err
	}
	if manifest.Version != j.Status.Version {
		return manifest, errors.New("staged version differs from the accepted update")
	}
	f, err := wintrust.OpenPrivateFile(j.installer(), false)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	return manifest, manifest.VerifyInstaller(f)
}

func recoverPendingUpdate(ctx context.Context, data string, log func(string), includeDesktop bool) {
	resolved, err := ResolveStore(data)
	if err != nil || CheckDirectory(resolved) != nil {
		return
	}
	lockCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	release, err := (Lock{Data: resolved, Name: "update"}).Acquire(lockCtx)
	if err != nil {
		return
	}
	defer release()
	j, err := readUpdateJournal(resolved)
	if err != nil {
		return
	}
	finishDesktop := includeDesktop && completedUpdate(j.Status.Phase) && !j.DesktopRestarted && !j.DesktopRecoveryAttempted
	if !j.Status.Busy() && !finishDesktop {
		return
	}
	live, err := updateRunnerAlive(j)
	if err != nil {
		log("update recovery process identity: " + err.Error())
		return
	}
	if live {
		return
	}
	if j.Status.Phase == "downloading" || j.Status.Phase == "verifying" {
		j.Status.Phase = "download-error"
		j.LastError = "download interrupted before installer launch"
		j.Status.Error = j.LastError
		if err := saveUpdateJournal(&j); err != nil {
			log(err.Error())
		}
		return
	}
	f, err := wintrust.OpenPrivateFile(j.runner(), false)
	if err != nil {
		if finishDesktop {
			log("update desktop recovery runner: " + err.Error())
			j.DesktopRecoveryAttempted = true
			_ = saveUpdateJournal(&j)
			return
		}
		failUpdateRecovery(&j, fmt.Errorf("update recovery runner: %w", err), log)
		return
	}
	f.Close()
	hash, err := hashNoFollowRegularFile(j.runner())
	if err != nil || hash != j.RunnerSHA256 {
		if finishDesktop {
			log("update desktop recovery runner hash differs")
			j.DesktopRecoveryAttempted = true
			_ = saveUpdateJournal(&j)
			return
		}
		failUpdateRecovery(&j, errors.New("update recovery runner hash does not match"), log)
		return
	}
	if finishDesktop {
		j.DesktopRecoveryAttempted = true
		if err := saveUpdateJournal(&j); err != nil {
			log(err.Error())
			return
		}
		if err := startJournalUpdater(&j); err != nil {
			log("resume committed update desktop handoff: " + err.Error())
		}
		return
	}
	if j.RecoveryAttempts != 0 {
		failUpdateRecovery(&j, errors.New("the recovery updater was interrupted; automatic recovery stopped"), log)
		return
	}
	j.RecoveryAttempts++
	if err := saveUpdateJournal(&j); err != nil {
		log(err.Error())
		return
	}
	if err := startJournalUpdater(&j); err != nil {
		failUpdateRecovery(&j, fmt.Errorf("restart interrupted updater: %w", err), log)
	}
}

func failUpdateRecovery(j *updateJournal, cause error, log func(string)) {
	j.Status.Phase, j.Status.Error, j.LastError = "failed", cause.Error(), cause.Error()
	log("update recovery: " + cause.Error())
	if err := saveUpdateJournal(j); err != nil {
		log("save update recovery result: " + err.Error())
	}
}
