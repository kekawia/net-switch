package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/control"
	"github.com/kekawia/net-switch/internal/faultpoint"
	"github.com/kekawia/net-switch/internal/localipc"
	"github.com/kekawia/net-switch/internal/platform/winapi"
	"github.com/kekawia/net-switch/internal/service"
	"github.com/kekawia/net-switch/internal/updates"
	"github.com/kekawia/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func readActiveUpdateSnapshot(data, operation string) (bool, error) {
	j, err := readUpdateJournal(data)
	if err != nil {
		return false, err
	}
	if j.Status.Operation != operation || !j.Status.Busy() {
		return false, errors.New("update operation is not active")
	}
	return true, nil
}

func authorizeUpdateRestart(data, operation string) error {
	j, err := readUpdateJournal(data)
	if err != nil {
		return err
	}
	if j.Status.Operation != operation {
		return errors.New("update operation changed")
	}
	switch j.Status.Phase {
	case "complete", "reboot-required", "rolled-back":
		return nil
	}
	return errors.New("update has not completed")
}

type updateControlSnapshot struct {
	Wanted   bool   `json:"wanted"`
	Routing  string `json:"routing"`
	Instance string `json:"engineInstanceId"`
	Owner    Owner  `json:"owner"`
}

func queryUpdateControl(ctx context.Context, operation string) (updateControlSnapshot, error) {
	var snapshot updateControlSnapshot
	rpc, err := ConnectStatus(ctx)
	if err != nil {
		return snapshot, err
	}
	defer rpc.Close()
	err = rpc.Call(ctx, map[string]any{"method": "update-snapshot", "key": operation}, &snapshot)
	return snapshot, err
}

func updateServicePaths() (map[string]string, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer manager.Disconnect()
	paths := map[string]string{}
	for _, name := range []string{service.Control, service.Engine} {
		s, err := manager.OpenService(name)
		if err != nil {
			return nil, err
		}
		config, err := s.Config()
		s.Close()
		if err != nil {
			return nil, err
		}
		paths[name] = config.BinaryPathName
	}
	return paths, nil
}

func checkUpdateServicePaths(paths map[string]string, config Config) error {
	if len(paths) != 2 {
		return errors.New("update requires exactly the two installed services")
	}
	for name, file := range map[string]string{service.Control: "netswitch.exe", service.Engine: "netswitch-engine.exe"} {
		args, err := windows.DecomposeCommandLine(paths[name])
		if err != nil || len(args) != 4 || !strings.EqualFold(filepath.Clean(args[0]), filepath.Join(config.Directory, file)) || args[1] != "service" || args[2] != "--data" || !strings.EqualFold(filepath.Clean(args[3]), config.Data) {
			return fmt.Errorf("unexpected executable path for %s", name)
		}
	}
	return nil
}

func readUpdateControlJournal(data string, value any) error {
	f, err := wintrust.OpenPrivateFile(filepath.Join(data, "control-journal.json"), false)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("control journal has trailing content")
	}
	return nil
}

func retainUpdateIntent(j *updateJournal) error {
	var record struct {
		Intent struct {
			Operation string `json:"operation"`
			Wanted    bool   `json:"wanted"`
		} `json:"updateIntent"`
	}
	if err := readUpdateControlJournal(j.Data, &record); err != nil {
		return err
	}
	if record.Intent.Operation == j.Status.Operation {
		j.RoutingWanted = record.Intent.Wanted
	}
	return saveUpdateJournal(j)
}

func seedRestoredUpdateIntent(j updateJournal) error {
	var record map[string]any
	if err := readUpdateControlJournal(j.Data, &record); err != nil {
		return err
	}
	record["wanted"] = false
	record["updateIntent"] = map[string]any{"operation": j.Status.Operation, "wanted": j.RoutingWanted}
	return Save(filepath.Join(j.Data, "control-journal.json"), record)
}

func prepareUpdate(ctx context.Context, j *updateJournal) error {
	if err := verifyKeptInstaller(j.AppDir, j.PreviousInstaller); err != nil {
		return err
	}
	snapshot, err := queryUpdateControl(ctx, j.Status.Operation)
	if err != nil {
		return err
	}
	if snapshot.Owner.User == "" {
		return errors.New("update has no enrolled owner")
	}
	paths, err := updateServicePaths()
	if err != nil {
		return err
	}
	if err := checkUpdateServicePaths(paths, j.Previous); err != nil {
		return err
	}
	j.Owner, j.ServicePaths = snapshot.Owner, paths
	j.RoutingWanted = snapshot.Wanted
	j.RoutingWasOn = snapshot.Wanted && (snapshot.Routing == "on" || snapshot.Routing == "starting")
	j.Captured = true
	if err := saveUpdateJournal(j); err != nil {
		return err
	}
	if err := service.StopForUpdate(ctx); err != nil {
		return err
	}
	faultpoint.Hit(j.Data, "update-stopped")
	if err := retainUpdateIntent(j); err != nil {
		return err
	}
	return captureUpdateData(j)
}

func installerUpdateArgs(j updateJournal) []string {
	version := j.Status.Version
	if j.Status.Phase == "rolling-back" {
		version = j.Status.PreviousVersion
	}
	return append([]string{"/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RESTARTEXITCODE=3010", "/LOG=" + filepath.Join(j.stageDir(), "install-"+version+".log"), "/DIR=" + j.AppDir, "/OWNER=" + j.Owner.User, "/DATA=" + j.Data, "/UPDATEOP=" + j.Status.Operation}, updateTestInstallerArgs(j.Data)...)
}

func verifyUpdateHealth(ctx context.Context, j updateJournal, version string) error {
	marker, exists, err := readNoFollowMarker(filepath.Join(j.AppDir, "current"))
	if err != nil || !exists {
		return errors.New("installer did not publish a current marker")
	}
	sub, err := ParseCurrentMarker(marker)
	if err != nil || sub != "app-"+version {
		return errors.New("installer published the wrong version")
	}
	config, err := LoadConfig(j.Data)
	if err != nil {
		return err
	}
	if !strings.EqualFold(config.Directory, filepath.Join(j.AppDir, sub)) {
		return errors.New("service configuration points at the wrong version")
	}
	paths, err := updateServicePaths()
	if err != nil {
		return err
	}
	if err := checkUpdateServicePaths(paths, config); err != nil {
		return err
	}
	var migration MigrationJournal
	if err := Read(filepath.Join(j.Data, "migration-journal.json"), &migration); err != nil {
		return err
	}
	if migration.Phase != "committed" || migration.Version != version || migration.UpdateOperation != j.Status.Operation {
		return errors.New("installer health transaction did not commit")
	}
	for {
		snapshot, err := queryUpdateControl(ctx, j.Status.Operation)
		if err != nil {
			return err
		}
		if snapshot.Owner.User != j.Owner.User {
			return errors.New("installed owner differs from update snapshot")
		}
		if !snapshot.Wanted && snapshot.Routing == "off" {
			return nil
		}
		if snapshot.Wanted && (!j.RoutingWasOn || (snapshot.Routing == "on" && snapshot.Instance != "")) {
			return nil
		}
		if err := localipc.Pause(ctx, 100*time.Millisecond); err != nil {
			return fmt.Errorf("updated routing did not settle: %w", err)
		}
	}
}

func rollbackUpdate(ctx context.Context, j *updateJournal) error {
	if !j.Captured {
		return nil
	}
	log := Log(j.Data, "netswitch-update")
	log("rollback: verify kept installer")
	if err := verifyKeptInstaller(j.AppDir, j.PreviousInstaller); err != nil {
		return err
	}
	log("rollback: stop services")
	if err := service.StopForUpdate(ctx); err != nil {
		return err
	}
	log("rollback: retain latest routing intent")
	if err := retainUpdateIntent(j); err != nil {
		return err
	}
	log("rollback: restore completed data snapshot")
	if err := restoreUpdateData(*j); err != nil {
		return err
	}
	if err := seedRestoredUpdateIntent(*j); err != nil {
		return err
	}
	log("rollback: run kept installer")
	code, err := runUpdateInstaller(ctx, keptInstallerPath(j.AppDir, j.PreviousInstaller), installerUpdateArgs(*j))
	log(fmt.Sprintf("rollback: installer returned code=%d error=%v", code, err))
	if err != nil {
		return err
	}
	if code != 0 && code != 3010 {
		return fmt.Errorf("previous installer exited %d", code)
	}
	paths, err := updateServicePaths()
	if err != nil {
		return err
	}
	for name, original := range j.ServicePaths {
		if paths[name] != original {
			return fmt.Errorf("rollback did not restore %s executable path", name)
		}
	}
	log("rollback: verify restored health")
	return verifyUpdateHealth(ctx, *j, j.Status.PreviousVersion)
}

func ApplyUpdate(ctx context.Context, data, operation string) error {
	inside, membershipErr := winapi.ProcessInJob(windows.CurrentProcess(), 0)
	if membershipErr != nil {
		return membershipErr
	}
	if inside {
		return errors.New("updater must run outside every job")
	}
	if !Administrator() {
		return errors.New("applying an update requires an administrator")
	}
	if !validUpdateOperation(operation) {
		return errors.New("invalid update operation")
	}
	resolved, err := ResolveStore(data)
	if err != nil {
		return err
	}
	release, err := (Lock{Data: resolved, Name: "update"}).Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	j, err := readUpdateJournal(resolved)
	if err != nil {
		return err
	}
	if j.Status.Operation != operation {
		return errors.New("update operation has changed")
	}
	log := Log(j.Data, "netswitch-update")
	log(fmt.Sprintf("update %s: runner %d entered phase %s", operation, j.RunnerPID, j.Status.Phase))
	if completedUpdate(j.Status.Phase) {
		return finishUpdateDesktop(ctx, &j)
	}
	if !j.Status.Busy() {
		return nil
	}
	pin, err := wintrust.PinPrivateDirectory(updateRoot(j.AppDir))
	if err != nil {
		return err
	}
	defer pin.Close()
	if j.Status.Phase == "ready" {
		if _, err := verifyStagedUpdate(j); err != nil {
			j.Status.Phase = "signature-error"
			j.LastError = err.Error()
			return errors.Join(err, saveUpdateJournal(&j))
		}
	}
	_, applyErr := updates.RunTransaction(ctx, j.Status, updates.TransactionOps{
		Save: func(status updates.Status) error {
			j.Status = status
			if err := saveUpdateJournal(&j); err != nil {
				return err
			}
			log("update phase: " + status.Phase)
			faultpoint.Hit(j.Data, "update-"+status.Phase)
			return nil
		},
		Prepare: func(ctx context.Context) error { return prepareUpdate(ctx, &j) },
		Install: func(ctx context.Context) (uint32, error) {
			log("update: run staged installer")
			code, err := runUpdateInstaller(ctx, j.installer(), installerUpdateArgs(j))
			log(fmt.Sprintf("update: installer returned code=%d error=%v", code, err))
			return code, err
		},
		Health: func(ctx context.Context) error {
			if err := verifyUpdateHealth(ctx, j, j.Status.Version); err != nil {
				return err
			}
			return updateTestHealthError(j.Data)
		},
		Keep: func(context.Context) error {
			_, err := loadKeptInstaller(j.AppDir, j.Status.Version, j.Architecture)
			return err
		},
		Rollback: func(ctx context.Context) error { return rollbackUpdate(ctx, &j) },
	})
	if applyErr != nil {
		log("update result: " + applyErr.Error())
		j.LastError = applyErr.Error()
		j.Status.Error = applyErr.Error()
		_ = saveUpdateJournal(&j)
	}
	if completedUpdate(j.Status.Phase) {
		if err := finishUpdateDesktop(ctx, &j); err != nil {
			Log(j.Data, service.Control)("update desktop restart: " + err.Error())
		}
	}
	return applyErr
}

func completedUpdate(phase string) bool {
	return phase == "complete" || phase == "reboot-required" || phase == "rolled-back"
}

func finishUpdateDesktop(ctx context.Context, j *updateJournal) error {
	if j.DesktopRestarted {
		return nil
	}
	if err := requestUpdateDesktopRestart(ctx, j.Status.Operation); err != nil {
		return err
	}
	j.DesktopRestarted = true
	return saveUpdateJournal(j)
}

// Cache the explicit installer's bytes before changing any services. This
// seeds the locally kept rollback source on the very first 1.0 installation.
func keepUpdateInstaller(appDir, version, source, architecture string) error {
	if source == "" {
		return nil
	}
	if !updates.CanonicalVersion(version) || (architecture != "x64" && architecture != "arm64") {
		return errors.New("invalid installer identity")
	}
	if err := ensureUpdateStore(appDir); err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if info.Size() <= 0 || info.Size() > updates.MaxInstallerSize {
		return errors.New("invalid kept installer size")
	}
	record := keptInstaller{Version: version, Architecture: architecture}
	target := keptInstallerPath(appDir, record)
	targetInfo, targetErr := os.Stat(target)
	if targetErr != nil || !os.SameFile(info, targetInfo) {
		if err := copyPrivateUpdateFile(source, target); err != nil {
			return err
		}
	}
	record.SHA256, err = hashNoFollowRegularFile(target)
	if err != nil {
		return err
	}
	return writePrivateUpdateJSON(filepath.Join(updateRoot(appDir), "kept", version+"-"+architecture+".json"), record)
}

func KeepUpdateInstaller(ctx context.Context, appDir, version, source, data, operation string) error {
	if !Administrator() {
		return errors.New("keeping an installer requires an administrator")
	}
	if operation != "" {
		return errors.New("installer retention is owned by the active install transaction")
	}
	resolved, err := ResolveStore(data)
	if err != nil {
		return err
	}
	release, err := (Lock{Data: resolved, Name: "update"}).Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	architecture, err := verifyHostArchitecture()
	if err != nil {
		return err
	}
	return keepUpdateInstaller(appDir, version, source, architecture)
}

func updateInstallContext(data, appDir, operation, version string) (bool, bool, error) {
	j, err := readUpdateJournal(data)
	if err != nil {
		return false, false, err
	}
	wantVersion := j.Status.Version
	if j.Status.Phase == "rolling-back" {
		wantVersion = j.Status.PreviousVersion
	} else if j.Status.Phase != "applying" {
		return false, false, errors.New("update is not applying an installer")
	}
	if j.Status.Operation != operation || !strings.EqualFold(j.AppDir, appDir) || version != wantVersion || !j.Captured {
		return false, false, errors.New("installer does not match the accepted update")
	}
	wanted := j.RoutingWanted
	if present, err := sessionPresence(data)(j.Owner.User, ^uint32(0)); err == nil && !present {
		wanted = false
	}
	return j.RoutingWasOn && wanted, wanted, nil
}

func runUpdateHealthCheck(ctx context.Context, config Config, core *control.Core, remote *Remote, log func(string)) bool {
	var migration MigrationJournal
	if Read(filepath.Join(config.Data, "migration-journal.json"), &migration) != nil || migration.Phase != "installed" || migration.UpdateOperation == "" {
		return false
	}
	runMigrationHealthCheck(ctx, config, core, remote, log)
	return true
}
