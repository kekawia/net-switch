package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/windowsundo"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RestoreWindows restores any Windows policy and adapter metric settings saved
// in windows-undo.json inside dataDir without starting Net Switch.
// Returns nil only when there was nothing to undo or every saved setting has
// been restored; any uncertainty or unreachable adapter returns a non-nil error
// so the uninstaller retains the machine folder.
func RestoreWindows(dataDir string) error {
	if !Administrator() {
		return errors.New("restoring Windows settings requires an administrator")
	}
	if dataDir == "" {
		dataDir = DefaultData()
	}
	var err error
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	resolved, err := ResolveStore(dataDir)
	if err != nil {
		return err
	}
	if strings.EqualFold(resolved, dataDir) {
		_, errMain := os.Lstat(resolved)
		_, errStage := os.Lstat(resolved + ".migrating")
		if errors.Is(errMain, os.ErrNotExist) && errors.Is(errStage, os.ErrNotExist) {
			fmt.Println("Nothing to undo.")
			return nil
		}
	}
	if err := win.PrepareMachineUninstall(dataDir, func(s string) { fmt.Fprintln(os.Stderr, s) }); err != nil {
		return err
	}
	resolved, err = ResolveStore(dataDir)
	if err != nil {
		return err
	}
	if err := CheckDirectory(resolved); err != nil {
		return err
	}
	return restoreWindowsWith(
		resolved,
		durableFiles{},
		os.Stdout,
		os.Stderr,
		func(value any) error {
			_, err := win.Execute("policy-set", map[string]any{"value": value})
			return err
		},
		func(alias string, rows []any) error {
			_, err := win.Execute("metrics-restore", map[string]any{"alias": alias, "metrics": rows})
			return err
		},
	)
}

func restoreWindowsWith(
	resolved string,
	files settings.Files,
	out io.Writer,
	errOut io.Writer,
	policySet func(any) error,
	metricsRestore func(string, []any) error,
) error {
	primaryPath := filepath.Join(resolved, "windows-undo.json")
	backupPath := primaryPath + ".bak"

	rawBytes, readErr := readStoreFile(primaryPath)
	if errors.Is(readErr, os.ErrNotExist) {
		if _, bakErr := os.Lstat(backupPath); !errors.Is(bakErr, os.ErrNotExist) {
			msg := fmt.Sprintf("The undo record in %s was damaged (primary file missing while backup exists). It is kept; nothing was changed.", resolved)
			fmt.Fprintln(errOut, msg)
			return errors.New(msg)
		}
		fmt.Fprintln(out, "Nothing to undo.")
		return nil
	}
	if readErr != nil {
		msg := fmt.Sprintf("Couldn't undo the Windows settings: %v", readErr)
		fmt.Fprintln(errOut, msg)
		return errors.New(msg)
	}

	rawObj, values, parseReason := parseStrictUndoRecord(rawBytes)
	if parseReason != "" {
		msg := fmt.Sprintf("The undo record in %s was damaged (%s). It is kept; nothing was changed.", resolved, parseReason)
		fmt.Fprintln(errOut, msg)
		return errors.New(msg)
	}
	aliases := windowsundo.Aliases(rawObj["metrics"])
	if err := windowsundo.Validate(values, aliases); err != nil {
		msg := fmt.Sprintf("The undo record in %s can't be trusted (%v). It is kept; nothing was changed.", resolved, err)
		fmt.Fprintln(errOut, msg)
		return errors.New(msg)
	}
	if !hasUndoChanges(values) {
		fmt.Fprintln(out, "Nothing to undo.")
		return nil
	}

	ioOptions := settings.Options{
		FileName:   "windows-undo.json",
		Defaults:   map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}},
		Files:      files,
		SyncFile:   syncFile,
		SyncParent: SyncDirectory,
	}
	undoStore := settings.New(resolved, ioOptions)
	loaded, err := undoStore.Load()
	if err != nil {
		msg := fmt.Sprintf("Couldn't undo the Windows settings: %v", err)
		fmt.Fprintln(errOut, msg)
		return errors.New(msg)
	}
	if undoStore.Recovery != nil {
		msg := fmt.Sprintf("The undo record in %s was damaged (%s). It is kept; nothing was changed.", resolved, undoStore.Recovery.Reason)
		fmt.Fprintln(errOut, msg)
		return errors.New(msg)
	}

	policy := js.Object(loaded["policy"])
	if policy == nil {
		policy = map[string]any{}
	}
	metrics := js.Object(loaded["metrics"])
	if metrics == nil {
		metrics = map[string]any{}
	}
	aliases = windowsundo.Aliases(undoStore.RawValues()["metrics"])

	if v, ok := policy["value"]; ok {
		if err := policySet(v); err != nil {
			msg := fmt.Sprintf("Couldn't undo the Windows settings: %v", err)
			fmt.Fprintln(errOut, msg)
			return errors.New(msg)
		}
		if _, err := undoStore.Update(map[string]any{"policy": map[string]any{}}); err != nil {
			msg := fmt.Sprintf("Couldn't undo the Windows settings: %v", err)
			fmt.Fprintln(errOut, msg)
			return errors.New(msg)
		}
	}

	unreachable := []string{}
	for _, alias := range aliases {
		rows, _ := metrics[alias].([]any)
		if len(rows) > 0 {
			if err := metricsRestore(alias, rows); err != nil {
				unreachable = append(unreachable, alias)
				continue
			}
		}
		delete(metrics, alias)
		if _, err := undoStore.Update(map[string]any{"metrics": windowsundo.MetricsJSON(metrics, aliases)}); err != nil {
			msg := fmt.Sprintf("Couldn't undo the Windows settings: %v", err)
			fmt.Fprintln(errOut, msg)
			return errors.New(msg)
		}
	}

	if len(unreachable) > 0 {
		msg := fmt.Sprintf("Undone, except the settings of %s: connect it again and run this again.", strings.Join(unreachable, " and "))
		fmt.Fprintln(out, msg)
		return errors.New(msg)
	}
	fmt.Fprintln(out, "Windows settings are back as they were before Net Switch changed them.")
	return nil
}

func parseStrictUndoRecord(rawBytes []byte) (map[string]json.RawMessage, map[string]any, string) {
	if !json.Valid(rawBytes) {
		return nil, nil, "Invalid JSON"
	}
	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	dec.UseNumber()
	var top any
	if err := dec.Decode(&top); err != nil {
		return nil, nil, err.Error()
	}
	if _, ok := top.(map[string]any); !ok {
		return nil, nil, "The JSON value is not a plain object."
	}
	var rawObj map[string]json.RawMessage
	if err := json.Unmarshal(rawBytes, &rawObj); err != nil {
		return nil, nil, err.Error()
	}
	decoded, err := js.Decode(rawBytes)
	if err != nil {
		return nil, nil, err.Error()
	}
	values := js.Object(decoded)
	if values == nil {
		return nil, nil, "The JSON value is not a plain object."
	}
	if _, hasMetrics := rawObj["metrics"]; !hasMetrics {
		values["metrics"] = map[string]any{}
	}
	if _, hasPolicy := rawObj["policy"]; !hasPolicy {
		values["policy"] = map[string]any{}
	}
	return rawObj, values, ""
}

func hasUndoChanges(values map[string]any) bool {
	if policy := js.Object(values["policy"]); policy != nil {
		if _, ok := policy["value"]; ok {
			return true
		}
	}
	if metrics := js.Object(values["metrics"]); metrics != nil {
		for _, v := range metrics {
			if rows, ok := v.([]any); ok && len(rows) > 0 {
				return true
			}
		}
	}
	return false
}

// CleanupMachineDataCommand removes the machine data folder, quarantined trees,
// and HKLM directory certificate after RestoreWindows succeeds or the user
// explicitly chooses to discard the Undo record.
func CleanupMachineDataCommand(dataDir string) error {
	if !Administrator() {
		return errors.New("cleaning machine data requires an administrator")
	}
	if dataDir == "" {
		dataDir = DefaultData()
	}
	var err error
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	return win.CleanupMachineData(dataDir, func(s string) { fmt.Fprintln(os.Stderr, s) })
}

// WhoamiCommand returns the calling token's user SID and account name, and
// optionally writes the JSON object to outPath without following reparse points.
func WhoamiCommand(outPath string, sidOutPath string) (Owner, error) {
	sid := CurrentUser()
	if sid == "" {
		return Owner{}, errors.New("could not read current process token user")
	}
	owner, err := ResolveOwner(sid)
	if err != nil {
		return Owner{}, err
	}
	if outPath != "" {
		absOut, err := filepath.Abs(outPath)
		if err != nil {
			return Owner{}, err
		}
		data, err := json.Marshal(owner)
		if err != nil {
			return Owner{}, err
		}
		data = append(data, '\n')
		if err := writeNoFollowUserFile(absOut, data); err != nil {
			return Owner{}, err
		}
	}
	if sidOutPath != "" {
		absSID, err := filepath.Abs(sidOutPath)
		if err != nil {
			return Owner{}, err
		}
		if err := writeNoFollowUserFile(absSID, []byte(owner.User+"\n")); err != nil {
			return Owner{}, err
		}
	}
	return owner, nil
}

// WriteInstallerError writes a single-line human-readable error message to path
// without following reparse points so Inno Setup's PrepareToInstall can surface it.
func WriteInstallerError(path string, err error) {
	if path == "" || err == nil {
		return
	}
	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		return
	}
	clean := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	_ = writeNoFollowUserFile(absPath, []byte(clean+"\n"))
}

func writeNoFollowUserFile(path string, data []byte) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES,
		0, nil, windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		f.Close()
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		f.Close()
		return fmt.Errorf("output path is not a plain single-link file: %s", path)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

const runSubkeySuffix = `\Software\Microsoft\Windows\CurrentVersion\Run`

func readOwnerRunKey(ownerSID string) (string, bool, error) {
	if ownerSID == "" {
		return "", false, nil
	}
	if _, err := windows.StringToSid(ownerSID); err != nil {
		return "", false, err
	}
	key, err := registry.OpenKey(registry.USERS, ownerSID+runSubkeySuffix, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer key.Close()
	val, _, err := key.GetStringValue("NetSwitch")
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return val, true, nil
}

func writeRawOwnerRunKey(ownerSID string, value string, present bool) error {
	if ownerSID == "" {
		return nil
	}
	if _, err := windows.StringToSid(ownerSID); err != nil {
		return err
	}
	hive, err := registry.OpenKey(registry.USERS, ownerSID, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	hive.Close()
	if !present {
		key, err := registry.OpenKey(registry.USERS, ownerSID+runSubkeySuffix, registry.SET_VALUE)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer key.Close()
		err = key.DeleteValue("NetSwitch")
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	key, _, err := registry.CreateKey(registry.USERS, ownerSID+runSubkeySuffix, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("NetSwitch", value)
}

func setOwnerRunKey(ownerSID, appDir string, on bool) error {
	if !on {
		return writeRawOwnerRunKey(ownerSID, "", false)
	}
	exe := filepath.Join(filepath.Clean(appDir), "netswitch-desktop.exe")
	value := windows.ComposeCommandLine([]string{exe, "--background"})
	return writeRawOwnerRunKey(ownerSID, value, true)
}
