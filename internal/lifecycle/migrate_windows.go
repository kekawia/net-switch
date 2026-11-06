package lifecycle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control"
	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/updates"
	"github.com/AyoubAchour/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ProfileCandidate describes one local Windows user profile discovered during
// Phase 1 pre-flight before stopping 0.3.x.
type ProfileCandidate struct {
	SID        string `json:"sid"`
	Account    string `json:"account"`
	ProfileDir string `json:"profileDir"`
	DataDir    string `json:"dataDir"`
	HasData    bool   `json:"hasData"`
	NonDefault bool   `json:"nonDefault"`
	Summary    string `json:"summary"`
	signature  string
}

// MigrateProfilesResult is returned by `netswitchctl migrate-profiles` so Inno
// Setup can prompt before stopping 0.3.x when multiple profiles differ.
type MigrateProfilesResult struct {
	Architecture    string             `json:"architecture"`
	Owner           Owner              `json:"owner"`
	Conflict        bool               `json:"conflict"`
	SelectedProfile string             `json:"selectedProfile"`
	Profiles        []ProfileCandidate `json:"profiles"`
}

// MigrateOptions configures `netswitchctl migrate`.
type MigrateOptions struct {
	AppDir   string
	StageDir string
	Version  string
	Owner    string
	Profile  string
	DataDir  string
	OutPath  string
}

// InstallVersionedOptions configures `netswitchctl install --app-dir ... --version ...`.
type InstallVersionedOptions struct {
	AppDir       string
	StageDir     string
	Version      string
	Owner        string
	DataDir      string
	Mode         string
	OwnerBackend string
}

// MigrationJournal persists every phase of the 0.3.x -> 1.0 transaction in
// %ProgramData%\Net Switch\migration-journal.json.
type MigrationJournal struct {
	Phase               string                  `json:"phase"`
	UpdatedAt           string                  `json:"updatedAt"`
	AppDir              string                  `json:"appDir"`
	Version             string                  `json:"version"`
	VersionDir          string                  `json:"versionDir"`
	DataDir             string                  `json:"dataDir"`
	StoreDir            string                  `json:"storeDir"`
	QuarantinePath      string                  `json:"quarantinePath,omitempty"`
	Owner               Owner                   `json:"owner"`
	SelectedProfile     string                  `json:"selectedProfile,omitempty"`
	SelectedDataDir     string                  `json:"selectedDataDir,omitempty"`
	ActiveLegacyUserDir string                  `json:"activeLegacyUserDir,omitempty"`
	ServerWasRunning    bool                    `json:"serverWasRunning"`
	RoutingWasOn        bool                    `json:"routingWasOn"`
	TrayWasRunning      bool                    `json:"trayWasRunning"`
	PriorRunValue       string                  `json:"priorRunValue,omitempty"`
	PriorRunPresent     bool                    `json:"priorRunPresent"`
	TasksSnapshot       win.LegacyTasksSnapshot `json:"tasksSnapshot"`
	HealthCheckID       string                  `json:"healthCheckId,omitempty"`
	LastError           string                  `json:"lastError,omitempty"`
}

type migrationHealthReport struct {
	ID               string `json:"id"`
	OK               bool   `json:"ok"`
	Error            string `json:"error,omitempty"`
	ControlPID       int    `json:"controlPid"`
	EngineInstanceID string `json:"engineInstanceId,omitempty"`
	Revision         uint64 `json:"revision"`
	RoutingStatus    string `json:"routingStatus"`
}

// LegacyRootEntries lists the exact 0.3.x files and directories at {app} that
// Phase 6 removes after switching {app}\current.
func LegacyRootEntries() []string {
	return []string{
		"runtime",
		"engine",
		"lib",
		"ui",
		"tools",
		"helper",
		"tray",
		"licenses",
		"docs",
		"launch.ps1",
		"tray.ps1",
		"server.mjs",
		"package.json",
		"LICENSE",
		"THIRD_PARTY_NOTICES.md",
	}
}

func expectedBinaryArchitecture() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Windows binary architecture %q", runtime.GOARCH)
	}
}

func verifyHostArchitecture() (string, error) {
	want, err := expectedBinaryArchitecture()
	if err != nil {
		return "", err
	}
	hostArch, err := win.Architecture()
	if err != nil {
		return "", fmt.Errorf("detect Windows architecture: %w", err)
	}
	if hostArch != want {
		return "", fmt.Errorf("binary architecture %s does not match Windows machine architecture %s", want, hostArch)
	}
	return hostArch, nil
}

// MigrateProfiles executes Phase 1 read-only discovery before stopping 0.3.x.
func MigrateProfiles(appDir, callerOwner string, outPath string, wizardOutPath string) (MigrateProfilesResult, error) {
	if !Administrator() {
		return MigrateProfilesResult{}, errors.New("migrate-profiles requires an administrator")
	}
	arch, err := verifyHostArchitecture()
	if err != nil {
		return MigrateProfilesResult{}, err
	}
	profiles, err := enumerateProfileCandidates()
	if err != nil {
		return MigrateProfilesResult{}, err
	}
	tasksSnap, _ := win.SnapshotLegacyTasks()
	owner, _ := resolveMigrationOwner(callerOwner, tasksSnap.OwnerSID, profiles)
	conflict, selected := selectMigrationProfile(owner.User, profiles)
	res := MigrateProfilesResult{
		Architecture:    arch,
		Owner:           owner,
		Conflict:        conflict,
		SelectedProfile: selected,
		Profiles:        profiles,
	}
	if outPath != "" {
		absOut, err := filepath.Abs(outPath)
		if err != nil {
			return res, err
		}
		b, err := json.Marshal(res)
		if err != nil {
			return res, err
		}
		b = append(b, '\n')
		if err := writeNoFollowUserFile(absOut, b); err != nil {
			return res, err
		}
	}
	if wizardOutPath != "" {
		absWiz, err := filepath.Abs(wizardOutPath)
		if err != nil {
			return res, err
		}
		var sb strings.Builder
		if conflict {
			sb.WriteString("CONFLICT=1\n")
		} else {
			sb.WriteString("CONFLICT=0\n")
		}
		sb.WriteString("OWNER=" + owner.User + "\n")
		sb.WriteString("SELECTED=" + selected + "\n")
		for _, p := range profiles {
			if conflict {
				if !p.NonDefault {
					continue
				}
			} else if !p.HasData {
				continue
			}
			cleanAccount := strings.NewReplacer("\r", " ", "\n", " ", "|", "/").Replace(p.Account)
			cleanSummary := strings.NewReplacer("\r", " ", "\n", " ").Replace(p.Summary)
			sb.WriteString(fmt.Sprintf("PROFILE=%s|%s (%s)\n", p.SID, cleanAccount, cleanSummary))
		}
		if err := writeNoFollowUserFile(absWiz, []byte(sb.String())); err != nil {
			return res, err
		}
	}
	return res, nil
}

func selectMigrationProfile(ownerSID string, profiles []ProfileCandidate) (conflict bool, selected string) {
	var withData []ProfileCandidate
	var nonDefault []ProfileCandidate
	signatures := map[string]bool{}
	for _, p := range profiles {
		if p.HasData {
			withData = append(withData, p)
		}
		if p.NonDefault {
			nonDefault = append(nonDefault, p)
			signatures[p.signature] = true
		}
	}
	conflict = len(nonDefault) > 1 && len(signatures) > 1
	for _, p := range nonDefault {
		if p.SID == ownerSID {
			return conflict, p.SID
		}
	}
	if len(nonDefault) > 0 {
		return conflict, nonDefault[0].SID
	}
	for _, p := range withData {
		if p.SID == ownerSID {
			return conflict, p.SID
		}
	}
	if len(withData) > 0 {
		return conflict, withData[0].SID
	}
	return false, ""
}

func resolveMigrationOwner(callerOwner, tasksOwnerSID string, profiles []ProfileCandidate) (Owner, error) {
	if strings.TrimSpace(callerOwner) != "" {
		return ResolveOwner(strings.TrimSpace(callerOwner))
	}
	if sid := activeWTSSessionOwnerSID(); sid != "" {
		if owner, err := ResolveOwner(sid); err == nil {
			return owner, nil
		}
	}
	if strings.TrimSpace(tasksOwnerSID) != "" {
		if owner, err := ResolveOwner(strings.TrimSpace(tasksOwnerSID)); err == nil {
			return owner, nil
		}
	}
	if self := CurrentUser(); self != "" {
		if owner, err := ResolveOwner(self); err == nil {
			return owner, nil
		}
	}
	var withData []ProfileCandidate
	for _, p := range profiles {
		if p.HasData {
			withData = append(withData, p)
		}
	}
	if len(withData) == 1 {
		if owner, err := ResolveOwner(withData[0].SID); err == nil {
			return owner, nil
		}
	}
	if len(profiles) == 1 {
		if owner, err := ResolveOwner(profiles[0].SID); err == nil {
			return owner, nil
		}
	}
	return Owner{}, errors.New("could not determine the interactive Windows user account; pass --owner")
}

func activeWTSSessionOwnerSID() string {
	var callerSession uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &callerSession); err == nil && callerSession != 0 {
		if sid, sErr := wtsSessionAccountSID(callerSession); sErr == nil && sid != "" {
			return sid
		}
		if sid, sErr := wtsSessionUser(callerSession); sErr == nil && sid != "" {
			return sid
		}
	}
	sessions, err := wtsSessions()
	if err != nil {
		return ""
	}
	// Prefer active Console/RDP sessions over disconnected ones.
	sort.SliceStable(sessions, func(i, j int) bool {
		iActive := sessions[i].state == windows.WTSActive
		jActive := sessions[j].state == windows.WTSActive
		if iActive != jActive {
			return iActive
		}
		iConsole := strings.EqualFold(sessions[i].name, "Console")
		jConsole := strings.EqualFold(sessions[j].name, "Console")
		if iConsole != jConsole {
			return iConsole
		}
		return sessions[i].id < sessions[j].id
	})
	for _, s := range sessions {
		if !userSession(s) {
			continue
		}
		if sid, err := wtsSessionAccountSID(s.id); err == nil && sid != "" {
			return sid
		}
		if sid, err := wtsSessionUser(s.id); err == nil && sid != "" {
			return sid
		}
	}
	return ""
}

var (
	wtsapi32                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInfoW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

func wtsQuerySessionString(sessionID uint32, infoClass uint32) (string, error) {
	if err := procWTSQuerySessionInfoW.Find(); err != nil {
		return "", err
	}
	var buf *uint16
	var bytesReturned uint32
	r1, _, callErr := syscall.SyscallN(
		procWTSQuerySessionInfoW.Addr(),
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 == 0 {
		if callErr != 0 {
			return "", callErr
		}
		return "", errors.New("WTSQuerySessionInformationW failed")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if buf == nil || bytesReturned < 2 {
		return "", nil
	}
	return windows.UTF16PtrToString(buf), nil
}

func wtsSessionAccountSID(sessionID uint32) (string, error) {
	const (
		wtsUserName   = 5
		wtsDomainName = 7
	)
	user, err := wtsQuerySessionString(sessionID, wtsUserName)
	if err != nil || strings.TrimSpace(user) == "" {
		return "", errors.New("no session user")
	}
	domain, _ := wtsQuerySessionString(sessionID, wtsDomainName)
	candidates := []string{user}
	if strings.TrimSpace(domain) != "" {
		candidates = append([]string{domain + `\` + user}, candidates...)
	}
	for _, account := range candidates {
		sid, _, kind, lErr := windows.LookupSID("", account)
		if lErr == nil && kind == windows.SidTypeUser {
			return sid.String(), nil
		}
	}
	return "", fmt.Errorf("could not resolve session user %q", user)
}

func enumerateProfileCandidates() ([]ProfileCandidate, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []ProfileCandidate
	for _, sidStr := range names {
		sid, err := windows.StringToSid(sidStr)
		if err != nil {
			continue
		}
		user, domain, kind, err := sid.LookupAccount("")
		if err != nil || kind != windows.SidTypeUser {
			continue
		}
		sub, err := registry.OpenKey(key, sidStr, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		rawPath, valType, pErr := sub.GetStringValue("ProfileImagePath")
		sub.Close()
		if pErr != nil || strings.TrimSpace(rawPath) == "" {
			continue
		}
		if valType == registry.EXPAND_SZ {
			if expanded, exErr := registry.ExpandString(rawPath); exErr == nil {
				rawPath = expanded
			}
		}
		profileDir := filepath.Clean(rawPath)
		if !filepath.IsAbs(profileDir) {
			continue
		}
		cand := inspectProfileData(sid, domain+`\`+user, profileDir)
		out = append(out, cand)
	}
	return out, nil
}

func inspectProfileData(profileSID *windows.SID, account, profileDir string) ProfileCandidate {
	dataDir := filepath.Join(profileDir, "AppData", "Local", "Net Switch")
	cand := ProfileCandidate{
		SID:        profileSID.String(),
		Account:    account,
		ProfileDir: profileDir,
		DataDir:    dataDir,
		Summary:    "no saved settings",
	}
	if ok := verifyProfileDirectory(dataDir, profileSID); !ok {
		return cand
	}
	settingsRaw, hasSettings := readProfileSettingsBytes(dataDir, profileSID)
	hasOther := false
	for _, name := range []string{"usage.json", "tray-settings.json", "server.json"} {
		if _, exists, err := readNoFollowProfileFile(filepath.Join(dataDir, name), profileSID, 4<<20); err == nil && exists {
			hasOther = true
		}
	}
	cand.HasData = hasSettings || hasOther
	if !hasSettings {
		if hasOther {
			cand.Summary = "default settings"
		}
		return cand
	}
	sig, nonDefault, summary := canonicalSettingsSignature(settingsRaw)
	cand.signature = sig
	cand.NonDefault = nonDefault
	cand.Summary = summary
	return cand
}

func trustedProfileObjectOwner(sd *windows.SECURITY_DESCRIPTOR, profileSID *windows.SID) bool {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	return profileSID != nil && owner.Equals(profileSID)
}

func verifyProfileDirectory(dir string, profileSID *windows.SID) bool {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return false
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	return trustedProfileObjectOwner(sd, profileSID)
}

func readNoFollowProfileFile(path string, profileSID *windows.SID, maxBytes int64) ([]byte, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return nil, false, fmt.Errorf("profile file is not a plain single-link file: %s", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, false, err
	}
	if !trustedProfileObjectOwner(sd, profileSID) {
		return nil, false, fmt.Errorf("profile file has unexpected owner: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, false, fmt.Errorf("profile file exceeds %d bytes: %s", maxBytes, path)
	}
	return data, true, nil
}

func readProfileSettingsBytes(dataDir string, profileSID *windows.SID) ([]byte, bool) {
	for _, name := range []string{"settings.json", "settings.json.bak"} {
		b, exists, err := readNoFollowProfileFile(filepath.Join(dataDir, name), profileSID, 4<<20)
		if err == nil && exists && isPlainJSONObject(b) {
			return b, true
		}
	}
	return nil, false
}

func isPlainJSONObject(b []byte) bool {
	if !json.Valid(b) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	_, ok := v.(map[string]any)
	return ok
}

type memSettingsFiles struct {
	files map[string][]byte
}

func (m *memSettingsFiles) ReadFile(p string) ([]byte, error) {
	b, ok := m.files[filepath.Base(p)]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (m *memSettingsFiles) WriteFile(p string, b []byte, _ os.FileMode) error {
	m.files[filepath.Base(p)] = bytes.Clone(b)
	return nil
}
func (m *memSettingsFiles) Rename(from, to string) error {
	m.files[filepath.Base(to)] = m.files[filepath.Base(from)]
	delete(m.files, filepath.Base(from))
	return nil
}
func (m *memSettingsFiles) Remove(p string) error {
	delete(m.files, filepath.Base(p))
	return nil
}

func canonicalSettingsSignature(raw []byte) (sig string, nonDefault bool, summary string) {
	defaultSig := normalizeSettingsBytes([]byte(`{}`))
	gotSig, lineCount, pinCount := normalizeSettingsDetail(raw)
	if gotSig == defaultSig {
		return gotSig, false, "default settings"
	}
	return gotSig, true, fmt.Sprintf("%d line(s), %d pinned app(s)", lineCount, pinCount)
}

func normalizeSettingsBytes(raw []byte) string {
	s, _, _ := normalizeSettingsDetail(raw)
	return s
}

func normalizeSettingsDetail(raw []byte) (string, int, int) {
	mem := &memSettingsFiles{files: map[string][]byte{}}
	if len(raw) > 0 {
		mem.files["settings.json"] = raw
	}
	store := settings.New("/mem", settings.Options{Files: mem})
	vals, err := store.Load()
	if err != nil {
		return string(raw), 0, 0
	}
	seq := 0
	if m := lines.MigrateSettings(vals, func() string {
		seq++
		return fmt.Sprintf("%08x", seq)
	}); m != nil {
		b, _ := js.Marshal(m.Lines)
		ll, _ := js.Decode(b)
		vals["lines"] = ll
		vals["appLines"] = m.AppLines
		if len(m.WaitingApps) > 0 {
			vals["waitingApps"] = m.WaitingApps
		}
		for _, k := range lines.LegacyKeys {
			delete(vals, k)
		}
	}
	delete(vals, "setupUndo")
	items := lines.NormalizeLines(vals["lines"])
	idMap := map[string]string{}
	for i := range items {
		canonicalID := fmt.Sprintf("%04x", i+1)
		idMap[items[i].ID] = canonicalID
		items[i].ID = canonicalID
	}
	var pins apps.Pins
	if existingPins, ok := vals["appLines"].(apps.Pins); ok {
		for _, p := range existingPins {
			if mapped, exists := idMap[p.LineID]; exists && p.Path != "" {
				pins = append(pins, apps.Pin{Path: strings.ToLower(p.Path), LineID: mapped})
			}
		}
	}
	mode := js.Text(vals["combineMode"])
	if mode != "auto" && mode != "manual" {
		mode = "auto"
	}
	ipv6 := js.Text(vals["ipv6"])
	if ipv6 != "auto" && ipv6 != "off" {
		ipv6 = "auto"
	}
	canon := map[string]any{
		"lines":           items,
		"appLines":        pins,
		"combine":         vals["combine"] == true,
		"combineMode":     mode,
		"probeTargets":    vals["probeTargets"],
		"ipv6":            ipv6,
		"checkForUpdates": vals["checkForUpdates"] != false,
		"skippedUpdate":   vals["skippedUpdate"],
	}
	encoded, _ := json.Marshal(canon)
	return string(encoded), len(items), len(pins)
}

// VerifyStageChecksums verifies every file in versionDir against STAGE-SHA256SUMS.txt
// without following reparse points or hard links.
func VerifyStageChecksums(versionDir string) error {
	sumFile := filepath.Join(versionDir, "STAGE-SHA256SUMS.txt")
	rawSums, err := readNoFollowRegularFile(sumFile, 4<<20)
	if err != nil {
		return fmt.Errorf("read STAGE-SHA256SUMS.txt: %w", err)
	}
	expected := map[string]string{}
	scan := bufio.NewScanner(bytes.NewReader(rawSums))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return fmt.Errorf("invalid STAGE-SHA256SUMS.txt entry %q", line)
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return fmt.Errorf("invalid SHA-256 hex in STAGE-SHA256SUMS.txt: %q", parts[0])
		}
		rel := strings.TrimSpace(parts[1])
		if rel == "" || strings.Contains(rel, `\`) || strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
			return fmt.Errorf("invalid path in STAGE-SHA256SUMS.txt: %q", rel)
		}
		expected[strings.ToLower(rel)] = strings.ToLower(parts[0])
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if len(expected) == 0 {
		return errors.New("STAGE-SHA256SUMS.txt is empty")
	}

	seen := map[string]bool{}
	var walk func(string, string) error
	walk = func(absDir, relPrefix string) error {
		entries, err := readDirNoFollow(absDir)
		if err != nil {
			return err
		}
		for _, name := range entries {
			absChild := filepath.Join(absDir, name)
			relChild := name
			if relPrefix != "" {
				relChild = relPrefix + "/" + name
			}
			isDir, err := isNoFollowDir(absChild)
			if err != nil {
				return err
			}
			if isDir {
				if err := walk(absChild, relChild); err != nil {
					return err
				}
				continue
			}
			if strings.EqualFold(relChild, "STAGE-SHA256SUMS.txt") {
				continue
			}
			key := strings.ToLower(relChild)
			wantHash, ok := expected[key]
			if !ok {
				return fmt.Errorf("unexpected unlisted file in staged directory: %s", relChild)
			}
			gotHash, err := hashNoFollowRegularFile(absChild)
			if err != nil {
				return err
			}
			if gotHash != wantHash {
				return fmt.Errorf("SHA-256 mismatch for %s: got %s, expected %s", relChild, gotHash, wantHash)
			}
			seen[key] = true
		}
		return nil
	}
	if err := walk(versionDir, ""); err != nil {
		return err
	}
	for key := range expected {
		if !seen[key] {
			return fmt.Errorf("staged file missing from %s: %s", versionDir, key)
		}
	}
	return nil
}

func readDirNoFollow(dir string) ([]string, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), dir)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return nil, fmt.Errorf("expected plain directory: %s", dir)
	}
	return f.Readdirnames(-1)
}

func isNoFollowDir(path string) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false, err
	}
	var info windows.ByHandleFileInformation
	infoErr := windows.GetFileInformationByHandle(h, &info)
	_ = windows.CloseHandle(h)
	if infoErr != nil {
		return false, infoErr
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("reparse points are refused: %s", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1 {
		return false, fmt.Errorf("hard links are refused: %s", path)
	}
	return info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, nil
}

func readNoFollowRegularFile(path string, maxBytes int64) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return nil, fmt.Errorf("expected plain single-link file: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds size limit: %s", path)
	}
	return data, nil
}

func hashNoFollowRegularFile(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return "", fmt.Errorf("expected plain single-link file: %s", path)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func copyNoFollowFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	inHandle, err := windows.CreateFile(srcPtr, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	inFile := os.NewFile(uintptr(inHandle), src)
	defer inFile.Close()
	var inInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(inHandle, &inInfo); err != nil {
		return err
	}
	if inInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || inInfo.NumberOfLinks != 1 {
		return fmt.Errorf("refusing to copy non-regular source %s", src)
	}

	tempDst := dst + "." + randomID()[:16] + ".tmp"
	dstPtr, err := windows.UTF16PtrFromString(tempDst)
	if err != nil {
		return err
	}
	outHandle, err := windows.CreateFile(dstPtr, windows.GENERIC_WRITE,
		0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	outFile := os.NewFile(uintptr(outHandle), tempDst)
	_, copyErr := io.Copy(outFile, inFile)
	syncErr := outFile.Sync()
	closeErr := outFile.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tempDst)
		return err
	}
	if err := durableRename(tempDst, dst); err != nil {
		_ = os.Remove(tempDst)
		return err
	}
	return nil
}

func copyStageTree(stageDir, appDir, versionDir string) error {
	stageDir, err := filepath.Abs(stageDir)
	if err != nil {
		return err
	}
	if err := VerifyStageChecksums(stageDir); err != nil {
		return fmt.Errorf("verify temporary stage %s: %w", stageDir, err)
	}
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return err
	}
	if err := removeNoFollowTree(versionDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return err
	}
	var copyWalk func(string, string) error
	copyWalk = func(srcDir, dstDir string) error {
		entries, err := readDirNoFollow(srcDir)
		if err != nil {
			return err
		}
		for _, name := range entries {
			sChild := filepath.Join(srcDir, name)
			dChild := filepath.Join(dstDir, name)
			isDir, err := isNoFollowDir(sChild)
			if err != nil {
				return err
			}
			if isDir {
				if err := os.MkdirAll(dChild, 0755); err != nil {
					return err
				}
				if err := copyWalk(sChild, dChild); err != nil {
					return err
				}
				continue
			}
			if err := copyNoFollowFile(sChild, dChild); err != nil {
				return err
			}
		}
		return nil
	}
	return copyWalk(stageDir, versionDir)
}

func removeNoFollowTree(target string) error {
	p, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	f := os.NewFile(uintptr(h), target)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		f.Close()
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		names, readErr := f.Readdirnames(-1)
		if readErr != nil {
			f.Close()
			return readErr
		}
		for _, child := range names {
			if err := removeNoFollowTree(filepath.Join(target, child)); err != nil {
				f.Close()
				return err
			}
		}
	}
	disposition := byte(1)
	delErr := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1)
	closeErr := f.Close()
	if delErr != nil {
		return fmt.Errorf("remove %s: %w", target, delErr)
	}
	return closeErr
}

type legacySessionFile struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

type legacyRuntimeProbe struct {
	ServerRunning bool
	RoutingOn     bool
	TrayRunning   bool
	ActiveUserDir string
	Sessions      []struct {
		UserDir string
		Session legacySessionFile
	}
}

func probeLegacyRuntime(appDir string, profiles []ProfileCandidate, preferredUserDir string) legacyRuntimeProbe {
	var out legacyRuntimeProbe
	out.TrayRunning = legacyTrayRunning(appDir)
	seen := map[string]bool{}
	var dirs []string
	if preferredUserDir != "" {
		dirs = append(dirs, preferredUserDir)
		seen[strings.ToLower(preferredUserDir)] = true
	}
	for _, p := range profiles {
		if p.HasData && !seen[strings.ToLower(p.DataDir)] {
			dirs = append(dirs, p.DataDir)
			seen[strings.ToLower(p.DataDir)] = true
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, dir := range dirs {
		raw, err := os.ReadFile(filepath.Join(dir, "server.json"))
		if err != nil || len(raw) > 64<<10 {
			continue
		}
		var sess legacySessionFile
		if json.Unmarshal(raw, &sess) != nil || sess.Port <= 0 || sess.Port > 65535 || sess.Token == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/state", sess.Port), nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Token", sess.Token)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var state struct {
			Routing struct {
				Status string `json:"status"`
				Wanted bool   `json:"wanted"`
			} `json:"routing"`
		}
		if json.Unmarshal(body, &state) != nil {
			continue
		}
		out.ServerRunning = true
		if out.ActiveUserDir == "" {
			out.ActiveUserDir = dir
		}
		if state.Routing.Status == "on" || state.Routing.Wanted {
			out.RoutingOn = true
			out.ActiveUserDir = dir
		}
		out.Sessions = append(out.Sessions, struct {
			UserDir string
			Session legacySessionFile
		}{UserDir: dir, Session: sess})
	}
	return out
}

func stopLegacyProcesses(appDir, dataDir string, probe legacyRuntimeProbe) error {
	client := &http.Client{Timeout: 10 * time.Second}
	for _, item := range probe.Sessions {
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/quit", item.Session.Port), strings.NewReader(`{}`))
		if err != nil {
			continue
		}
		req.Header.Set("X-Token", item.Session.Token)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
	}

	if pidBytes, err := os.ReadFile(filepath.Join(dataDir, "engine.pid")); err == nil && len(pidBytes) <= 64 {
		if pid64, pErr := strconv.ParseUint(strings.TrimSpace(string(pidBytes)), 10, 32); pErr == nil && pid64 > 0 {
			stopLegacyEnginePID(uint32(pid64), filepath.Join(appDir, "engine"))
		}
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		remaining, err := terminateMatchingLegacyProcesses(appDir)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("legacy Net Switch processes did not stop: %s", strings.Join(remaining, ", "))
		}
		time.Sleep(300 * time.Millisecond)
	}
	retireCtx, cancelRetire := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelRetire()
	if err := winengine.RecordRetiredLegacyAdapter(retireCtx); err != nil {
		return fmt.Errorf("retire legacy Net Switch adapter: %w", err)
	}
	return nil
}

func stopLegacyEnginePID(pid uint32, engineDir string) {
	query, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(query)
	exePath := queryHandleImagePath(query)
	if exePath == "" || !strings.EqualFold(filepath.Dir(exePath), filepath.Clean(engineDir)) {
		return
	}
	_ = win.StopProcess(pid, exePath)
}

func legacyTrayRunning(appDir string) bool {
	matches, _ := findMatchingLegacyProcesses(appDir, true)
	return len(matches) > 0
}

func terminateMatchingLegacyProcesses(appDir string) ([]string, error) {
	return findMatchingLegacyProcesses(appDir, false)
}

func findMatchingLegacyProcesses(appDir string, trayOnly bool) ([]string, error) {
	appDir = filepath.Clean(appDir)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	helperExe := filepath.Join(appDir, "helper", "netswitch-helper.exe")
	engineDir := filepath.Join(appDir, "engine")
	trayExe := filepath.Join(appDir, "tray", "NetSwitchTray.exe")
	nodeExe := filepath.Join(appDir, "runtime", "node.exe")
	serverScript := filepath.Join(appDir, "server.mjs")
	trayScript := filepath.Join(appDir, "tray.ps1")
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	ps64 := filepath.Join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	ps32 := filepath.Join(sysRoot, "SysWOW64", "WindowsPowerShell", "v1.0", "powershell.exe")

	selfPID := uint32(os.Getpid())
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return nil, nil
		}
		return nil, err
	}

	var matched []string
	for {
		pid := entry.ProcessID
		if pid != 0 && pid != 4 && pid != selfPID {
			func() {
				query, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
				if err != nil {
					return
				}
				defer windows.CloseHandle(query)
				exePath := queryHandleImagePath(query)
				if exePath == "" {
					return
				}
				isTray := strings.EqualFold(exePath, trayExe) ||
					((strings.EqualFold(exePath, ps64) || strings.EqualFold(exePath, ps32)) && processCommandLineContains(query, trayScript))
				isOther := !trayOnly && (strings.EqualFold(exePath, helperExe) ||
					(strings.EqualFold(filepath.Dir(exePath), engineDir) && strings.EqualFold(filepath.Ext(exePath), ".exe")) ||
					(strings.EqualFold(exePath, nodeExe) && processCommandLineContains(query, serverScript)))
				if !isTray && !isOther {
					return
				}
				if trayOnly {
					matched = append(matched, fmt.Sprintf("%s (%d)", filepath.Base(exePath), pid))
					return
				}
				term, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
				if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
					return
				}
				if err != nil {
					matched = append(matched, fmt.Sprintf("%s (%d: %v)", filepath.Base(exePath), pid, err))
					return
				}
				defer windows.CloseHandle(term)
				_ = windows.TerminateProcess(term, 1)
				waitRes, waitErr := windows.WaitForSingleObject(term, 3000)
				if waitErr != nil || waitRes != windows.WAIT_OBJECT_0 {
					matched = append(matched, fmt.Sprintf("%s (%d)", filepath.Base(exePath), pid))
				}
			}()
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return matched, err
		}
	}
	return matched, nil
}

func queryHandleImagePath(query windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(query, 0, &buf[0], &size); err != nil || size == 0 {
		return ""
	}
	return filepath.Clean(windows.UTF16ToString(buf[:size]))
}

func processCommandLineContains(query windows.Handle, needle string) bool {
	const processCommandLineInformation = 60
	words := 1024 // 8 KiB initial 8-byte-aligned buffer
	for attempt := 0; attempt < 3; attempt++ {
		backing := make([]uint64, words)
		byteLen := uint32(len(backing) * 8)
		var retLen uint32
		err := windows.NtQueryInformationProcess(
			query,
			processCommandLineInformation,
			unsafe.Pointer(&backing[0]),
			byteLen,
			&retLen,
		)
		if err == nil {
			ustr := (*windows.NTUnicodeString)(unsafe.Pointer(&backing[0]))
			if ustr.Length == 0 || ustr.Buffer == nil {
				runtime.KeepAlive(backing)
				return false
			}
			start := uintptr(unsafe.Pointer(&backing[0]))
			end := start + uintptr(byteLen)
			bufAddr := uintptr(unsafe.Pointer(ustr.Buffer))
			if bufAddr < start || bufAddr+uintptr(ustr.Length) > end {
				runtime.KeepAlive(backing)
				return false
			}
			cmdLine := windows.UTF16ToString(unsafe.Slice(ustr.Buffer, int(ustr.Length/2)))
			runtime.KeepAlive(backing)
			return strings.Contains(strings.ToLower(cmdLine), strings.ToLower(needle))
		}
		runtime.KeepAlive(backing)
		if retLen == 0 || retLen > 128*1024 {
			return false
		}
		words = int((retLen + 15) / 8)
	}
	return false
}

type capturedUserFiles struct {
	Settings     []byte
	Usage        []byte
	TraySettings []byte
}

func captureSelectedProfileFiles(profileSIDStr, userDataDir string) (capturedUserFiles, error) {
	var out capturedUserFiles
	if profileSIDStr == "" || userDataDir == "" {
		return out, nil
	}
	sid, err := windows.StringToSid(profileSIDStr)
	if err != nil {
		return out, err
	}
	if !verifyProfileDirectory(userDataDir, sid) {
		return out, nil
	}
	if b, ok := readProfileSettingsBytes(userDataDir, sid); ok {
		out.Settings = b
	}
	if b, exists, err := readNoFollowProfileFile(filepath.Join(userDataDir, "usage.json"), sid, 4<<20); err == nil && exists && isPlainJSONObject(b) {
		out.Usage = b
	}
	if b, exists, err := readNoFollowProfileFile(filepath.Join(userDataDir, "tray-settings.json"), sid, 4<<20); err == nil && exists && isPlainJSONObject(b) {
		out.TraySettings = b
	}
	return out, nil
}

func writeCapturedFilesToStore(storeDir string, captured capturedUserFiles) error {
	opts := settings.Options{Files: durableFiles{}, SyncFile: syncFile, SyncParent: SyncDirectory}
	if len(captured.Settings) > 0 {
		p := filepath.Join(storeDir, "settings.json")
		if err := settings.AtomicWrite(p, captured.Settings, opts); err != nil {
			return fmt.Errorf("write migrated settings.json: %w", err)
		}
		if err := settings.AtomicWrite(p+".bak", captured.Settings, opts); err != nil {
			return fmt.Errorf("write migrated settings.json.bak: %w", err)
		}
	}
	if len(captured.Usage) > 0 {
		p := filepath.Join(storeDir, "usage.json")
		if err := settings.AtomicWrite(p, captured.Usage, opts); err != nil {
			return fmt.Errorf("write migrated usage.json: %w", err)
		}
	}
	if len(captured.TraySettings) > 0 {
		p := filepath.Join(storeDir, "tray-settings.json")
		if err := settings.AtomicWrite(p, captured.TraySettings, opts); err != nil {
			return fmt.Errorf("write migrated tray-settings.json: %w", err)
		}
	}
	return nil
}

func publishRootDesktopFiles(appDir, version, versionDir string) error {
	markerPath := filepath.Join(appDir, "current")
	markerContent := []byte("app-" + version + "\n")
	tempMarker := markerPath + "." + randomID()[:16] + ".tmp"
	if err := writeNoFollowUserFile(tempMarker, markerContent); err != nil {
		return err
	}
	if err := durableRename(tempMarker, markerPath); err != nil {
		_ = os.Remove(tempMarker)
		return err
	}
	if err := copyNoFollowFile(filepath.Join(versionDir, "netswitch-desktop.exe"), filepath.Join(appDir, "netswitch-desktop.exe")); err != nil {
		return err
	}
	srcIcon := filepath.Join(versionDir, "assets", "net-switch.ico")
	if _, err := os.Lstat(srcIcon); err == nil {
		if err := copyNoFollowFile(srcIcon, filepath.Join(appDir, "assets", "net-switch.ico")); err != nil {
			return err
		}
	}
	return wintrust.HardenRootFiles(appDir)
}

func shouldFaultAtPhase(phase string) error {
	target := strings.TrimSpace(os.Getenv("NETSWITCH_MIGRATE_FAULT_PHASE"))
	if target != "" && target == phase {
		return fmt.Errorf("injected migration fault at phase %s", phase)
	}
	return nil
}

// Migrate executes the 7-phase 0.3.x -> 1.0 journaled migration transaction.
func Migrate(ctx context.Context, opts MigrateOptions) error {
	if !Administrator() {
		return errors.New("migrate requires an administrator")
	}
	if opts.AppDir == "" {
		return errors.New("--app-dir is required")
	}
	version := strings.TrimPrefix(strings.TrimSpace(opts.Version), "v")
	if updates.ParseVersion(version) == nil {
		return fmt.Errorf("invalid target version %q", opts.Version)
	}
	appDir, err := filepath.Abs(opts.AppDir)
	if err != nil {
		return err
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = DefaultData()
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	versionDir := filepath.Join(appDir, "app-"+version)

	// Reconcile any interrupted pre-commit journal before starting a fresh attempt.
	if resolvedExisting, rErr := ResolveStore(dataDir); rErr == nil {
		if CheckDirectory(resolvedExisting) == nil {
			var prev MigrationJournal
			if Read(filepath.Join(resolvedExisting, "migration-journal.json"), &prev) == nil {
				if prev.Phase == "committed" && prev.Version == version {
					return nil
				}
				if prev.Phase != "" && prev.Phase != "committed" && prev.Phase != "rolled_back" {
					if rbErr := rollbackMigration(ctx, prev); rbErr != nil {
						return fmt.Errorf("recover interrupted migration (%s): %w", prev.Phase, rbErr)
					}
				}
			}
		}
	}

	// Phase 1: Checked (architecture, desktop owner, and profile ambiguity).
	profRes, err := MigrateProfiles(appDir, opts.Owner, "", "")
	if err != nil {
		return err
	}
	owner := profRes.Owner
	if owner.User == "" {
		return errors.New("could not determine the interactive Windows user account; pass --owner")
	}
	selectedSID := strings.TrimSpace(opts.Profile)
	if selectedSID != "" {
		resolvedSelected, sErr := ResolveOwner(selectedSID)
		if sErr != nil {
			return fmt.Errorf("invalid --profile %q: %w", selectedSID, sErr)
		}
		selectedSID = resolvedSelected.User
	} else {
		if profRes.Conflict {
			return errors.New("multiple Windows profiles have differing Net Switch settings; choose one interactively or pass --profile")
		}
		selectedSID = profRes.SelectedProfile
	}
	selectedDataDir := ""
	for _, p := range profRes.Profiles {
		if p.SID == selectedSID {
			selectedDataDir = p.DataDir
			break
		}
	}
	ownerProfileDataDir := ""
	for _, p := range profRes.Profiles {
		if p.SID == owner.User {
			ownerProfileDataDir = p.DataDir
			break
		}
	}

	// Phase 2: Staged (stage files if requested, harden, verify SHA-256 & installation, snapshot tasks & runtime).
	if opts.StageDir != "" {
		if err := copyStageTree(opts.StageDir, appDir, versionDir); err != nil {
			_ = removeNoFollowTree(versionDir)
			return err
		}
	}
	if err := wintrust.HardenInstallation(appDir, versionDir); err != nil {
		if opts.StageDir != "" {
			_ = removeNoFollowTree(versionDir)
		}
		return err
	}
	if err := VerifyStageChecksums(versionDir); err != nil {
		if opts.StageDir != "" {
			_ = removeNoFollowTree(versionDir)
		}
		return err
	}
	if err := service.CheckInstallation(versionDir); err != nil {
		if opts.StageDir != "" {
			_ = removeNoFollowTree(versionDir)
		}
		return err
	}
	tasksSnap, err := win.SnapshotLegacyTasks()
	if err != nil {
		return fmt.Errorf("snapshot legacy scheduled tasks: %w", err)
	}
	priorRunVal, priorRunPresent, err := readOwnerRunKey(owner.User)
	if err != nil {
		return fmt.Errorf("read owner Run key: %w", err)
	}
	preferredProbeDir := selectedDataDir
	if preferredProbeDir == "" {
		preferredProbeDir = ownerProfileDataDir
	}
	probe := probeLegacyRuntime(appDir, profRes.Profiles, preferredProbeDir)
	activeLegacyDir := probe.ActiveUserDir
	if activeLegacyDir == "" {
		if selectedDataDir != "" {
			activeLegacyDir = selectedDataDir
		} else {
			activeLegacyDir = ownerProfileDataDir
		}
	}

	journal := MigrationJournal{
		Phase:               "staged",
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		AppDir:              appDir,
		Version:             version,
		VersionDir:          versionDir,
		DataDir:             dataDir,
		Owner:               owner,
		SelectedProfile:     selectedSID,
		SelectedDataDir:     selectedDataDir,
		ActiveLegacyUserDir: activeLegacyDir,
		ServerWasRunning:    probe.ServerRunning,
		RoutingWasOn:        probe.RoutingOn,
		TrayWasRunning:      probe.TrayRunning,
		PriorRunValue:       priorRunVal,
		PriorRunPresent:     priorRunPresent,
		TasksSnapshot:       tasksSnap,
	}

	var releaseLock func() error
	failAndRollback := func(cause error) error {
		if releaseLock != nil {
			_ = releaseLock()
			releaseLock = nil
		}
		rbErr := rollbackMigration(ctx, journal)
		if rbErr != nil {
			return fmt.Errorf("migration failed at phase %s (%w); rollback encountered errors: %v", journal.Phase, cause, rbErr)
		}
		return fmt.Errorf("migration failed at phase %s and rolled back to 0.3.x: %w", journal.Phase, cause)
	}

	if err := shouldFaultAtPhase("staged"); err != nil {
		return failAndRollback(err)
	}

	// Phase 3: Stopped (graceful API quit, then exact-identity process stop, then capture flushed user files).
	if err := stopLegacyProcesses(appDir, dataDir, probe); err != nil {
		return failAndRollback(err)
	}
	journal.Phase = "stopped"
	captured, err := captureSelectedProfileFiles(selectedSID, selectedDataDir)
	if err != nil {
		return failAndRollback(err)
	}
	if err := shouldFaultAtPhase("stopped"); err != nil {
		return failAndRollback(err)
	}

	// Phase 4: Copied (prepare certified machine store, quarantine legacy %ProgramData%\Net Switch untouched, write migrated records).
	storeDir, err := PrepareStore(dataDir)
	if err != nil {
		return failAndRollback(err)
	}
	journal.StoreDir = storeDir
	quarantinePath, qErr := win.ReadDirectoryQuarantine(storeDir)
	if qErr != nil {
		return failAndRollback(qErr)
	}
	journal.QuarantinePath = quarantinePath

	releaseLock, err = (Lock{Data: storeDir, Name: "migration"}).Acquire(ctx)
	if err != nil {
		return failAndRollback(err)
	}
	defer func() {
		if releaseLock != nil {
			_ = releaseLock()
		}
	}()

	saveJournal := func(phase string) error {
		journal.Phase = phase
		journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return Save(filepath.Join(storeDir, "migration-journal.json"), journal)
	}
	if err := writeCapturedFilesToStore(storeDir, captured); err != nil {
		return failAndRollback(err)
	}
	if err := saveJournal("copied"); err != nil {
		return failAndRollback(err)
	}
	if err := shouldFaultAtPhase("copied"); err != nil {
		return failAndRollback(err)
	}

	// Phase 5: Installed -> Healthy (configure & install services, enrol owner, set Run key, start Control, verify engine attach & revision).
	cfg := Config{Directory: versionDir, Data: storeDir, Mode: "tun"}
	if err := Save(filepath.Join(storeDir, "service-config.json"), cfg); err != nil {
		return failAndRollback(err)
	}
	if _, err := Enroll(ctx, storeDir, owner.User); err != nil {
		return failAndRollback(err)
	}
	if err := service.InstallOrReplace(ctx, service.Config{Directory: versionDir, Data: storeDir, Owner: owner.User, Native: true}); err != nil {
		return failAndRollback(err)
	}
	if tasksSnap.SignInReady {
		if err := setOwnerRunKey(owner.User, appDir, true); err != nil {
			return failAndRollback(err)
		}
	}
	journal.HealthCheckID = randomID()
	_ = os.Remove(filepath.Join(storeDir, "migration-health.json"))
	_ = os.Remove(filepath.Join(storeDir, "migration-health.json.bak"))
	if err := saveJournal("installed"); err != nil {
		return failAndRollback(err)
	}
	if err := shouldFaultAtPhase("installed"); err != nil {
		return failAndRollback(err)
	}

	if err := service.Activate(ctx); err != nil {
		return failAndRollback(err)
	}
	if err := waitForMigrationHealth(ctx, storeDir, owner.User, journal.HealthCheckID); err != nil {
		return failAndRollback(err)
	}
	if err := saveJournal("healthy"); err != nil {
		return failAndRollback(err)
	}
	if err := shouldFaultAtPhase("healthy"); err != nil {
		return failAndRollback(err)
	}

	// Phase 6: Committed (publish {app}\current and root launcher, remove legacy scheduled tasks and retired 0.3.x root files).
	if err := publishRootDesktopFiles(appDir, version, versionDir); err != nil {
		return failAndRollback(err)
	}
	if err := win.RemoveLegacyTasks(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: remove legacy scheduled tasks after commit: %v\n", err)
	}
	for _, entry := range LegacyRootEntries() {
		if err := removeNoFollowTree(filepath.Join(appDir, entry)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: remove retired 0.3.x path %s: %v\n", entry, err)
		}
	}
	if err := saveJournal("committed"); err != nil {
		return err
	}
	if opts.OutPath != "" {
		b, _ := json.Marshal(journal)
		b = append(b, '\n')
		_ = writeNoFollowUserFile(opts.OutPath, b)
	}
	return nil
}

func waitForMigrationHealth(ctx context.Context, storeDir, ownerSID, healthCheckID string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	statusOK := false
	for {
		if !statusOK {
			if rpc, err := ConnectStatus(waitCtx); err == nil {
				var state struct {
					Owner Owner `json:"owner"`
				}
				callErr := rpc.Call(waitCtx, map[string]any{"method": "status"}, &state)
				rpc.Close()
				if callErr == nil && state.Owner.User == ownerSID {
					statusOK = true
				}
			}
		}
		var report migrationHealthReport
		if err := Read(filepath.Join(storeDir, "migration-health.json"), &report); err == nil && report.ID == healthCheckID {
			if !report.OK {
				return fmt.Errorf("post-migration health check failed: %s", report.Error)
			}
			if statusOK && report.EngineInstanceID != "" && report.Revision >= 1 {
				return nil
			}
		}
		if err := localipc.Pause(waitCtx, 150*time.Millisecond); err != nil {
			return fmt.Errorf("timed out waiting for migration health check (statusOK=%t): %w", statusOK, err)
		}
	}
}

// runMigrationHealthCheck runs inside ControlService (as LocalSystem) when
// migration-journal.json is in phase "installed", verifying NetSwitchEngine
// attachment, revision compilation, and (if routing was active in 0.3.x) live
// routing resume before Phase 6 commits.
func runMigrationHealthCheck(ctx context.Context, c Config, core *control.Core, remote *Remote, log func(string)) {
	var mj MigrationJournal
	if err := Read(filepath.Join(c.Data, "migration-journal.json"), &mj); err != nil {
		return
	}
	if mj.Phase != "installed" || mj.HealthCheckID == "" {
		return
	}
	var existing migrationHealthReport
	if err := Read(filepath.Join(c.Data, "migration-health.json"), &existing); err == nil && existing.ID == mj.HealthCheckID {
		return
	}

	hCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	writeReport := func(rep migrationHealthReport) {
		rep.ID = mj.HealthCheckID
		rep.ControlPID = os.Getpid()
		if err := Save(filepath.Join(c.Data, "migration-health.json"), rep); err != nil {
			log("write migration-health.json failed: " + err.Error())
		}
	}

	remote.mu.Lock()
	desired := remote.desired
	remote.mu.Unlock()
	if desired == nil || desired.Number == 0 {
		writeReport(migrationHealthReport{OK: false, Error: "Control has no compiled desired revision"})
		return
	}
	if _, err := nativeRevision(*desired); err != nil {
		writeReport(migrationHealthReport{OK: false, Error: "compile native revision: " + err.Error()})
		return
	}

	if mj.RoutingWasOn && len(desired.Policy.Lines) > 0 {
		if err := core.Routing(hCtx, true); err != nil {
			writeReport(migrationHealthReport{OK: false, Error: "resume routing on native engine: " + err.Error()})
			return
		}
		snap := remote.Snapshot()
		if snap.Status != "on" || snap.Instance == "" || snap.AppliedRevision == 0 {
			writeReport(migrationHealthReport{OK: false, Error: fmt.Sprintf("unexpected engine snapshot after resume: status=%s instance=%q rev=%d", snap.Status, snap.Instance, snap.AppliedRevision)})
			return
		}
		writeReport(migrationHealthReport{
			OK:               true,
			EngineInstanceID: snap.Instance,
			Revision:         snap.AppliedRevision,
			RoutingStatus:    snap.Status,
		})
		return
	}

	if err := remote.Attach(hCtx, true); err != nil {
		writeReport(migrationHealthReport{OK: false, Error: "attach native engine: " + err.Error()})
		return
	}
	remote.mu.Lock()
	instance := remote.instance
	epoch := remote.epoch
	remote.mu.Unlock()
	if instance == "" || epoch == 0 {
		_ = remote.Stop(hCtx)
		writeReport(migrationHealthReport{OK: false, Error: "engine attached without valid instance/epoch"})
		return
	}
	if err := remote.Stop(hCtx); err != nil {
		log("stop idle engine after migration probe: " + err.Error())
	}
	remote.mu.Lock()
	remote.stopping = false
	remote.mu.Unlock()

	writeReport(migrationHealthReport{
		OK:               true,
		EngineInstanceID: instance,
		Revision:         desired.Number,
		RoutingStatus:    "off",
	})
}

func rollbackMigration(ctx context.Context, journal MigrationJournal) error {
	rbCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var errs []error

	if err := service.Uninstall(rbCtx); err != nil {
		errs = append(errs, fmt.Errorf("uninstall 1.0 services: %w", err))
	}
	if journal.StoreDir != "" && CheckDirectory(journal.StoreDir) == nil {
		shortCtx, stopShort := context.WithTimeout(rbCtx, 5*time.Second)
		_ = Cleanup(shortCtx, journal.StoreDir)
		stopShort()
	}
	if journal.Owner.User != "" {
		if err := writeRawOwnerRunKey(journal.Owner.User, journal.PriorRunValue, journal.PriorRunPresent); err != nil {
			errs = append(errs, fmt.Errorf("restore Run key: %w", err))
		}
	}
	if journal.StoreDir != "" || journal.QuarantinePath != "" {
		if err := win.RollbackPreparedDirectory(journal.DataDir, journal.StoreDir, journal.QuarantinePath, func(s string) { fmt.Fprintln(os.Stderr, s) }); err != nil {
			errs = append(errs, fmt.Errorf("rollback machine store: %w", err))
		}
	}
	if journal.VersionDir != "" && strings.EqualFold(filepath.Dir(journal.VersionDir), journal.AppDir) && isVersionedAppSubdir(filepath.Base(journal.VersionDir)) {
		if err := removeNoFollowTree(journal.VersionDir); err != nil {
			errs = append(errs, fmt.Errorf("remove uncommitted version directory %s: %w", journal.VersionDir, err))
		}
	}
	if err := win.RestoreLegacyTasks(journal.TasksSnapshot); err != nil {
		errs = append(errs, fmt.Errorf("restore legacy scheduled tasks: %w", err))
	}
	if journal.ServerWasRunning {
		if err := restartLegacyRuntime(rbCtx, journal); err != nil {
			errs = append(errs, fmt.Errorf("restart 0.3.x runtime: %w", err))
		}
	}
	_ = ctx
	return errors.Join(errs...)
}

func restartLegacyRuntime(ctx context.Context, journal MigrationJournal) error {
	userDir := journal.ActiveLegacyUserDir
	if userDir == "" {
		return errors.New("cannot restart 0.3.x server without user data directory")
	}
	nodeExe := filepath.Join(journal.AppDir, "runtime", "node.exe")
	serverScript := filepath.Join(journal.AppDir, "server.mjs")
	if _, err := os.Stat(nodeExe); err != nil {
		return err
	}
	if _, err := os.Stat(serverScript); err != nil {
		return err
	}

	_ = os.Remove(filepath.Join(userDir, "server.json"))
	startedByTask := false
	if journal.TasksSnapshot.Present && journal.TasksSnapshot.ServerXML != "" {
		if win.RunServerTask() == nil {
			if _, ok := waitLegacyServerPing(userDir, 10*time.Second); ok {
				startedByTask = true
			}
		}
	}
	if !startedByTask {
		cmdArgs := []string{nodeExe, serverScript, "--user-data", userDir, "--machine-data", journal.DataDir}
		if err := spawnDetachedProcess(nodeExe, cmdArgs, journal.AppDir, windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT); err != nil {
			return err
		}
	}
	sess, ok := waitLegacyServerPing(userDir, 45*time.Second)
	if !ok {
		return errors.New("0.3.x server did not answer /api/ping after rollback")
	}
	if journal.RoutingWasOn {
		client := &http.Client{Timeout: 30 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/routing", sess.Port), strings.NewReader(`{"on":true}`))
		if err != nil {
			return err
		}
		req.Header.Set("X-Token", sess.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("resume 0.3.x routing: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("resume 0.3.x routing returned HTTP %d", resp.StatusCode)
		}
	}
	if journal.TrayWasRunning {
		trayExe := filepath.Join(journal.AppDir, "tray", "NetSwitchTray.exe")
		if _, err := os.Stat(trayExe); err == nil && CurrentUser() == journal.Owner.User {
			_ = spawnDetachedProcess(trayExe, []string{trayExe, "-DataDir", userDir}, journal.AppDir, windows.CREATE_UNICODE_ENVIRONMENT)
		}
	}
	return nil
}

func waitLegacyServerPing(userDir string, timeout time.Duration) (legacySessionFile, bool) {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(filepath.Join(userDir, "server.json")); err == nil && len(raw) <= 64<<10 {
			var sess legacySessionFile
			if json.Unmarshal(raw, &sess) == nil && sess.Port > 0 && sess.Token != "" {
				req, reqErr := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/ping", sess.Port), nil)
				if reqErr == nil {
					req.Header.Set("X-Token", sess.Token)
					if resp, doErr := client.Do(req); doErr == nil {
						_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
						resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							return sess, true
						}
					}
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return legacySessionFile{}, false
}

func spawnDetachedProcess(exePath string, args []string, workDir string, flags uint32) error {
	appName, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return err
	}
	wd, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(appName, cmdLine, nil, nil, false, flags, nil, wd, &si, &pi); err != nil {
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	return nil
}

// InstallVersioned installs or upgrades a versioned Windows layout at
// {appDir}\app-{version}, publishes {appDir}\current and the top-level desktop
// launcher, verifies Control readiness when an owner is enrolled, and rolls back
// to the previous app-<ver> if replacing an existing 1.0 installation fails.
func InstallVersioned(ctx context.Context, opts InstallVersionedOptions) error {
	if !Administrator() {
		return errors.New("install requires an administrator")
	}
	if _, err := verifyHostArchitecture(); err != nil {
		return err
	}
	version := strings.TrimPrefix(strings.TrimSpace(opts.Version), "v")
	if updates.ParseVersion(version) == nil {
		return fmt.Errorf("invalid version %q", opts.Version)
	}
	appDir, err := filepath.Abs(opts.AppDir)
	if err != nil {
		return err
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = DefaultData()
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	mode := opts.Mode
	if mode == "" {
		mode = "tun"
	}
	if mode != "tun" {
		return errors.New("native service qualification requires tun mode")
	}
	versionDir := filepath.Join(appDir, "app-"+version)

	var prevSub string
	if rawMarker, exists, mErr := readNoFollowMarker(filepath.Join(appDir, "current")); mErr == nil && exists {
		if parsed, pErr := ParseCurrentMarker(rawMarker); pErr == nil && parsed != "app-"+version {
			prevSub = parsed
		}
	}

	wasRoutingOn := queryCurrentControlRoutingWanted(ctx)

	if opts.StageDir != "" {
		if err := copyStageTree(opts.StageDir, appDir, versionDir); err != nil {
			_ = removeNoFollowTree(versionDir)
			return err
		}
	}
	if err := wintrust.HardenInstallation(appDir, versionDir); err != nil {
		if opts.StageDir != "" && prevSub != "app-"+version {
			_ = removeNoFollowTree(versionDir)
		}
		return err
	}
	if _, statErr := os.Lstat(filepath.Join(versionDir, "STAGE-SHA256SUMS.txt")); statErr == nil {
		if err := VerifyStageChecksums(versionDir); err != nil {
			if opts.StageDir != "" && prevSub != "app-"+version {
				_ = removeNoFollowTree(versionDir)
			}
			return err
		}
	}
	if err := service.CheckInstallation(versionDir); err != nil {
		if opts.StageDir != "" && prevSub != "app-"+version {
			_ = removeNoFollowTree(versionDir)
		}
		return err
	}

	storeDir, err := PrepareStore(dataDir)
	if err != nil {
		return err
	}
	if err := refuseStandInStore(storeDir); err != nil {
		return err
	}

	existingOwner, err := LoadOwner(storeDir)
	if err != nil {
		return err
	}
	owner := existingOwner
	if strings.TrimSpace(opts.Owner) != "" {
		owner, err = Enroll(ctx, storeDir, strings.TrimSpace(opts.Owner))
		if err != nil {
			return err
		}
	} else if owner.User == "" {
		if resolved, rErr := resolveMigrationOwner("", "", nil); rErr == nil && resolved.User != "" {
			if enrolled, eErr := Enroll(ctx, storeDir, resolved.User); eErr == nil {
				owner = enrolled
			}
		}
	}

	rollbackToPrev := func(cause error) error {
		if prevSub == "" {
			return cause
		}
		prevDir := filepath.Join(appDir, prevSub)
		if service.CheckInstallation(prevDir) == nil {
			_ = Save(filepath.Join(storeDir, "service-config.json"), Config{Directory: prevDir, Data: storeDir, Mode: mode, OwnerBackend: opts.OwnerBackend})
			_ = service.InstallOrReplace(ctx, service.Config{Directory: prevDir, Data: storeDir, Owner: owner.User, Native: true})
			prevVer := strings.TrimPrefix(prevSub, "app-")
			_ = publishRootDesktopFiles(appDir, prevVer, prevDir)
			if owner.User != "" {
				_ = service.Activate(ctx)
			}
		}
		if prevSub != "app-"+version {
			_ = removeNoFollowTree(versionDir)
		}
		return cause
	}

	// Stop existing services cleanly before switching service-config.json.
	if err := service.Uninstall(ctx); err != nil {
		return rollbackToPrev(err)
	}
	cfg := Config{Directory: versionDir, Data: storeDir, Mode: mode, OwnerBackend: opts.OwnerBackend}
	if err := Save(filepath.Join(storeDir, "service-config.json"), cfg); err != nil {
		return rollbackToPrev(err)
	}
	if err := service.InstallOrReplace(ctx, service.Config{Directory: versionDir, Data: storeDir, Owner: owner.User, Native: true}); err != nil {
		return rollbackToPrev(err)
	}
	if err := publishRootDesktopFiles(appDir, version, versionDir); err != nil {
		return rollbackToPrev(err)
	}
	if owner.User != "" {
		healthID := randomID()
		_ = os.Remove(filepath.Join(storeDir, "migration-health.json"))
		_ = os.Remove(filepath.Join(storeDir, "migration-health.json.bak"))
		_ = Save(filepath.Join(storeDir, "migration-journal.json"), MigrationJournal{
			Phase:         "installed",
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			AppDir:        appDir,
			Version:       version,
			VersionDir:    versionDir,
			DataDir:       dataDir,
			StoreDir:      storeDir,
			Owner:         owner,
			RoutingWasOn:  wasRoutingOn,
			HealthCheckID: healthID,
		})
		if err := service.Activate(ctx); err != nil {
			return rollbackToPrev(err)
		}
		if err := waitForMigrationHealth(ctx, storeDir, owner.User, healthID); err != nil {
			return rollbackToPrev(err)
		}
		_ = Save(filepath.Join(storeDir, "migration-journal.json"), MigrationJournal{
			Phase:         "committed",
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			AppDir:        appDir,
			Version:       version,
			VersionDir:    versionDir,
			DataDir:       dataDir,
			StoreDir:      storeDir,
			Owner:         owner,
			RoutingWasOn:  wasRoutingOn,
			HealthCheckID: healthID,
		})
	}
	pruneSupersededVersionDirs(appDir, "app-"+version, prevSub)
	return nil
}

func queryCurrentControlRoutingWanted(ctx context.Context) bool {
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rpc, err := ConnectStatus(qCtx)
	if err != nil {
		return false
	}
	defer rpc.Close()
	var raw json.RawMessage
	if err := rpc.Call(qCtx, map[string]any{"method": "status"}, &raw); err != nil {
		return false
	}
	return parseControlStatusRoutingWanted(raw)
}

func parseControlStatusRoutingWanted(raw []byte) bool {
	var state struct {
		Routing json.RawMessage `json:"routing"`
	}
	if json.Unmarshal(raw, &state) != nil || len(state.Routing) == 0 {
		return false
	}
	var statusStr string
	if json.Unmarshal(state.Routing, &statusStr) == nil {
		return statusStr == "on" || statusStr == "starting"
	}
	var obj struct {
		Status string `json:"status"`
		Wanted bool   `json:"wanted"`
	}
	if json.Unmarshal(state.Routing, &obj) == nil {
		return obj.Status == "on" || obj.Status == "starting" || obj.Wanted
	}
	return false
}

func pruneSupersededVersionDirs(appDir, keepCurrent, keepPrev string) {
	entries, err := readDirNoFollow(appDir)
	if err != nil {
		return
	}
	for _, name := range entries {
		if !isVersionedAppSubdir(name) {
			continue
		}
		if strings.EqualFold(name, keepCurrent) || (keepPrev != "" && strings.EqualFold(name, keepPrev)) {
			continue
		}
		target := filepath.Join(appDir, name)
		_ = StopInstalledDesktopProcesses(target)
		_ = removeNoFollowTree(target)
	}
}

// StopInstalledDesktopProcesses terminates netswitch-desktop.exe instances
// whose full verified executable path sits inside rootDir (either
// {rootDir}\netswitch-desktop.exe or {rootDir}\app-*\netswitch-desktop.exe).
func StopInstalledDesktopProcesses(rootDir string) error {
	if rootDir == "" {
		return nil
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return err
	}
	absRoot = filepath.Clean(absRoot)
	deadline := time.Now().Add(10 * time.Second)
	for {
		remaining, err := stopDesktopUnderRootOnce(absRoot)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("desktop processes still running under %s: %s", absRoot, strings.Join(remaining, ", "))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func stopDesktopUnderRootOnce(absRoot string) ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	selfPID := uint32(os.Getpid())
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return nil, nil
		}
		return nil, err
	}
	var remaining []string
	for {
		pid := entry.ProcessID
		if pid != 0 && pid != 4 && pid != selfPID {
			func() {
				query, qErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
				if qErr != nil {
					return
				}
				defer windows.CloseHandle(query)
				exePath := queryHandleImagePath(query)
				if !matchesInstalledDesktopExe(exePath, absRoot) {
					return
				}
				term, tErr := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
				if errors.Is(tErr, windows.ERROR_INVALID_PARAMETER) {
					return
				}
				if tErr != nil {
					remaining = append(remaining, fmt.Sprintf("%d", pid))
					return
				}
				defer windows.CloseHandle(term)
				_ = windows.TerminateProcess(term, 1)
				w, wErr := windows.WaitForSingleObject(term, 3000)
				if wErr != nil || w != windows.WAIT_OBJECT_0 {
					remaining = append(remaining, fmt.Sprintf("%d", pid))
				}
			}()
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return remaining, err
		}
	}
	return remaining, nil
}

func matchesInstalledDesktopExe(exePath, absRoot string) bool {
	if !strings.EqualFold(filepath.Base(exePath), "netswitch-desktop.exe") {
		return false
	}
	dir := filepath.Clean(filepath.Dir(exePath))
	if strings.EqualFold(dir, absRoot) {
		return true
	}
	if strings.EqualFold(filepath.Dir(dir), absRoot) && isVersionedAppSubdir(filepath.Base(dir)) {
		return true
	}
	return false
}

// HardenInstallRootCommand hardens {app}\current, {app}\netswitch-desktop.exe,
// and {app}\assets\net-switch.ico after Inno Setup finishes writing [Files].
func HardenInstallRootCommand(appDir string) error {
	if !Administrator() {
		return errors.New("harden-root requires an administrator")
	}
	absApp, err := filepath.Abs(appDir)
	if err != nil {
		return err
	}
	return wintrust.HardenRootFiles(absApp)
}
