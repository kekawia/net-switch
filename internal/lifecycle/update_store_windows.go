package lifecycle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/updates"
	"github.com/kekawia/net-switch/internal/wintrust"
)

type keptInstaller struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
}

type updateSnapshotFile struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	SHA256  string `json:"sha256,omitempty"`
}

type updateJournal struct {
	Status                   updates.Status       `json:"status"`
	AppDir                   string               `json:"appDir"`
	Data                     string               `json:"data"`
	Architecture             string               `json:"architecture"`
	Previous                 Config               `json:"previous"`
	Owner                    Owner                `json:"owner"`
	ServicePaths             map[string]string    `json:"servicePaths,omitempty"`
	RoutingWasOn             bool                 `json:"routingWasOn"`
	RoutingWanted            bool                 `json:"routingWanted"`
	Captured                 bool                 `json:"captured"`
	SnapshotComplete         bool                 `json:"snapshotComplete"`
	Files                    []updateSnapshotFile `json:"files,omitempty"`
	PreviousInstaller        keptInstaller        `json:"previousInstaller"`
	RunnerSHA256             string               `json:"runnerSha256"`
	RunnerPID                uint32               `json:"runnerPid,omitempty"`
	RunnerCreated            int64                `json:"runnerCreated,omitempty"`
	RecoveryAttempts         int                  `json:"recoveryAttempts,omitempty"`
	DesktopRestarted         bool                 `json:"desktopRestarted,omitempty"`
	DesktopRecoveryAttempted bool                 `json:"desktopRecoveryAttempted,omitempty"`
	Dismissed                bool                 `json:"dismissed,omitempty"`
	LastError                string               `json:"lastError,omitempty"`
	UpdatedAt                time.Time            `json:"updatedAt"`
}

func updateRoot(appDir string) string { return filepath.Join(appDir, "updates") }
func (j updateJournal) stageDir() string {
	return filepath.Join(updateRoot(j.AppDir), "staging", j.Status.Operation)
}
func (j updateJournal) installer() string { return filepath.Join(j.stageDir(), "installer.exe") }
func (j updateJournal) runner() string {
	return filepath.Join(updateRoot(j.AppDir), "runner", j.Status.Operation, "netswitchctl.exe")
}
func (j updateJournal) snapshotDir() string {
	return filepath.Join(j.Data, "update-snapshots", j.Status.Operation)
}
func keptInstallerPath(appDir string, record keptInstaller) string {
	return filepath.Join(updateRoot(appDir), "kept", "NetSwitch-Setup-"+record.Version+"-"+record.Architecture+".exe")
}

func validUpdateOperation(operation string) bool {
	b, err := hex.DecodeString(operation)
	return err == nil && len(b) == 32 && strings.ToLower(operation) == operation
}

func ensureUpdateStore(appDir string) error {
	if !filepath.IsAbs(appDir) {
		return errors.New("update installation root must be absolute")
	}
	for _, path := range []string{updateRoot(appDir), filepath.Join(updateRoot(appDir), "staging"), filepath.Join(updateRoot(appDir), "kept"), filepath.Join(updateRoot(appDir), "runner")} {
		if err := wintrust.EnsurePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func copyPrivateUpdateFile(src, dst string) error {
	return copyNoFollowFileWith(src, dst, func(path string) (*os.File, error) { return wintrust.OpenPrivateFile(path, true) })
}

func writePrivateUpdateJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateUpdateBytes(path, raw)
}

func writePrivateUpdateBytes(path string, raw []byte) error {
	temp := path + "." + randomID() + ".tmp"
	f, err := wintrust.OpenPrivateFile(temp, true)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := durableRename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func stageUpdateBundle(j updateJournal, bundle updates.Bundle) error {
	for _, file := range []struct {
		name  string
		bytes []byte
	}{
		{"netswitch-release-key.json", bundle.Key}, {"netswitch-release-key.json.minisig", bundle.KeySignature},
		{"update-manifest-" + j.Architecture + ".json", bundle.Manifest}, {"update-manifest-" + j.Architecture + ".json.minisig", bundle.ManifestSignature},
	} {
		if err := writePrivateUpdateBytes(filepath.Join(j.stageDir(), file.name), file.bytes); err != nil {
			return err
		}
	}
	return nil
}

func readUpdateBundle(j updateJournal) (updates.Bundle, error) {
	var bundle updates.Bundle
	for _, file := range []struct {
		name  string
		bytes *[]byte
	}{
		{"netswitch-release-key.json", &bundle.Key}, {"netswitch-release-key.json.minisig", &bundle.KeySignature},
		{"update-manifest-" + j.Architecture + ".json", &bundle.Manifest}, {"update-manifest-" + j.Architecture + ".json.minisig", &bundle.ManifestSignature},
	} {
		f, err := wintrust.OpenPrivateFile(filepath.Join(j.stageDir(), file.name), false)
		if err != nil {
			return bundle, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, updates.MaxMetadataSize+1))
		closeErr := f.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return bundle, err
		}
		if int64(len(raw)) > updates.MaxMetadataSize {
			return bundle, errors.New("staged metadata exceeds size limit")
		}
		*file.bytes = raw
	}
	return bundle, nil
}

func readPrivateUpdateJSON(path string, value any) error {
	f, err := wintrust.OpenPrivateFile(path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("private update record is too large")
	}
	return json.Unmarshal(raw, value)
}

func readUpdateJournal(data string) (updateJournal, error) {
	var journal updateJournal
	path := filepath.Join(data, "update-journal.json")
	err := Read(path, &journal)
	if err != nil {
		journal = updateJournal{}
		err = Read(path+".bak", &journal)
	}
	if err != nil {
		return journal, err
	}
	if !validUpdateOperation(journal.Status.Operation) || !filepath.IsAbs(journal.AppDir) || journal.Data != data ||
		!updates.CanonicalVersion(journal.Status.Version) || !updates.CanonicalVersion(journal.Status.PreviousVersion) ||
		!updates.IsNewer(journal.Status.Version, journal.Status.PreviousVersion) ||
		(journal.Architecture != "x64" && journal.Architecture != "arm64") || journal.Previous.Data != data ||
		journal.PreviousInstaller.Version != journal.Status.PreviousVersion || journal.PreviousInstaller.Architecture != journal.Architecture ||
		journal.RecoveryAttempts < 0 || journal.RecoveryAttempts > 1 ||
		!strings.EqualFold(journal.Previous.Directory, filepath.Join(journal.AppDir, "app-"+journal.Status.PreviousVersion)) {
		return journal, errors.New("invalid protected update journal")
	}
	switch journal.Status.Phase {
	case "downloading", "verifying", "ready", "preparing", "snapshotted", "applying", "checking", "rolling-back", "complete", "reboot-required", "rolled-back", "failed", "download-error", "signature-error":
	default:
		return journal, errors.New("invalid protected update phase")
	}
	if journal.Captured {
		if journal.Owner.User == "" {
			return journal, errors.New("captured update has no owner")
		}
		if err := checkUpdateServicePaths(journal.ServicePaths, journal.Previous); err != nil {
			return journal, err
		}
	}
	return journal, nil
}

func saveUpdateJournal(j *updateJournal) error {
	j.UpdatedAt = time.Now().UTC()
	return Save(filepath.Join(j.Data, "update-journal.json"), j)
}

// Run only under update.lock after refusing a pending operation. Old staging,
// snapshots and runners are no longer recovery inputs. Keep the installed
// version's installer and the last recorded previous version, never every
// installer the machine has downloaded over its lifetime.
func pruneUpdateArtifacts(appDir, data, current string, log func(string)) {
	previous := current
	if old, err := readUpdateJournal(data); err == nil {
		previous = old.Status.PreviousVersion
		if old.Captured && old.Status.Phase == "failed" {
			return
		}
	}
	for _, parent := range []string{filepath.Join(updateRoot(appDir), "staging"), filepath.Join(updateRoot(appDir), "runner"), filepath.Join(data, "update-snapshots")} {
		entries, err := readDirNoFollow(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			log("update cleanup: " + err.Error())
			continue
		}
		for _, name := range entries {
			if !validUpdateOperation(name) {
				continue
			}
			if err := removeNoFollowTree(filepath.Join(parent, name)); err != nil {
				log("update cleanup: " + err.Error())
			}
		}
	}
	kept := filepath.Join(updateRoot(appDir), "kept")
	entries, err := readDirNoFollow(kept)
	if err != nil {
		log("kept installer cleanup: " + err.Error())
		return
	}
	for _, name := range entries {
		identity := strings.TrimPrefix(name, "NetSwitch-Setup-")
		identity = strings.TrimSuffix(strings.TrimSuffix(identity, ".json"), ".exe")
		version, arch, ok := strings.Cut(identity, "-")
		if !ok || !updates.CanonicalVersion(version) || (arch != "x64" && arch != "arm64") || version == current || version == previous {
			continue
		}
		if name != version+"-"+arch+".json" && name != "NetSwitch-Setup-"+version+"-"+arch+".exe" {
			continue
		}
		if err := removeNoFollowTree(filepath.Join(kept, name)); err != nil {
			log("kept installer cleanup: " + err.Error())
		}
	}
}

func verifyKeptInstaller(appDir string, expected keptInstaller) error {
	if !updates.CanonicalVersion(expected.Version) || (expected.Architecture != "x64" && expected.Architecture != "arm64") {
		return errors.New("invalid kept installer identity")
	}
	var record keptInstaller
	path := filepath.Join(updateRoot(appDir), "kept", expected.Version+"-"+expected.Architecture+".json")
	if err := readPrivateUpdateJSON(path, &record); err != nil {
		return err
	}
	if record != expected {
		return errors.New("kept installer record changed")
	}
	f, err := wintrust.OpenPrivateFile(keptInstallerPath(appDir, record), false)
	if err != nil {
		return err
	}
	f.Close()
	hash, err := hashNoFollowRegularFile(keptInstallerPath(appDir, record))
	if err != nil {
		return err
	}
	if !strings.EqualFold(hash, record.SHA256) {
		return errors.New("kept installer hash does not match")
	}
	return nil
}

func loadKeptInstaller(appDir, version, architecture string) (keptInstaller, error) {
	var record keptInstaller
	if !updates.CanonicalVersion(version) || (architecture != "x64" && architecture != "arm64") {
		return record, errors.New("invalid kept installer version")
	}
	if err := readPrivateUpdateJSON(filepath.Join(updateRoot(appDir), "kept", version+"-"+architecture+".json"), &record); err != nil {
		return record, err
	}
	if record.Version != version || record.Architecture != architecture {
		return record, errors.New("kept installer identity differs")
	}
	return record, verifyKeptInstaller(appDir, record)
}

func updateDataFiles() []string {
	var files []string
	for _, name := range []string{"settings.json", "usage.json", "windows-undo.json", "tray-settings.json", "owner.json", "control-journal.json", "proxy-secrets.json", "service-config.json", "migration-journal.json", "migration-health.json"} {
		files = append(files, name, name+".bak")
	}
	return files
}

func captureUpdateData(j *updateJournal) error {
	for _, path := range []string{filepath.Join(j.Data, "update-snapshots"), j.snapshotDir()} {
		if err := wintrust.EnsurePrivateDirectory(path); err != nil {
			return err
		}
	}
	j.Files = nil
	for _, name := range updateDataFiles() {
		source, target := filepath.Join(j.Data, name), filepath.Join(j.snapshotDir(), name)
		record := updateSnapshotFile{Name: name}
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			j.Files = append(j.Files, record)
			continue
		} else if err != nil {
			return err
		}
		if err := copyPrivateUpdateFile(source, target); err != nil {
			return err
		}
		hash, err := hashNoFollowRegularFile(target)
		if err != nil {
			return err
		}
		record.Present, record.SHA256 = true, hash
		j.Files = append(j.Files, record)
	}
	j.SnapshotComplete = true
	return saveUpdateJournal(j)
}

func restoreUpdateData(j updateJournal) error {
	if !j.SnapshotComplete {
		return nil
	}
	names := updateDataFiles()
	if len(j.Files) != len(names) {
		return errors.New("incomplete update snapshot manifest")
	}
	// Check every snapshot before replacing even one live file.
	for i, record := range j.Files {
		if record.Name != names[i] {
			return errors.New("invalid update snapshot file name")
		}
		if record.Present {
			source := filepath.Join(j.snapshotDir(), record.Name)
			f, err := wintrust.OpenPrivateFile(source, false)
			if err != nil {
				return err
			}
			f.Close()
			hash, err := hashNoFollowRegularFile(source)
			if err != nil {
				return fmt.Errorf("update snapshot %s: %w", record.Name, err)
			}
			if hash != record.SHA256 {
				return fmt.Errorf("update snapshot %s failed hash verification", record.Name)
			}
		}
	}
	for _, record := range j.Files {
		target := filepath.Join(j.Data, record.Name)
		if !record.Present {
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		// Stream the snapshot through the same durable copy path. Large usage
		// histories do not need to fit into the updater's heap.
		if err := copyPrivateUpdateFile(filepath.Join(j.snapshotDir(), record.Name), target); err != nil {
			return err
		}
	}
	return nil
}
