// Package xdg discovers Linux desktop applications, derives Net Switch app
// identities, and resolves application icons from freedesktop directories.
package xdg

import (
	"bufio"
	"encoding/base64"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
)

const maxIconBytes = 512 * 1024

// Options configures directory search roots for XDG desktop discovery.
// Zero values fall back to the standard environment-derived locations via DefaultOptions.
type Options struct {
	AppDirs  []string
	IconDirs []string
	PathDirs []string
}

// Entry describes one discovered Linux desktop application entry.
type Entry struct {
	Name     string
	Identity string
	Path     string
	Key      string
	Icon     string
}

// DefaultOptions returns standard freedesktop search paths for the current user.
func DefaultOptions() Options {
	home, _ := os.UserHomeDir()
	dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if dataHome == "" && home != "" {
		dataHome = filepath.Join(home, ".local", "share")
	}

	rawDataDirs := strings.TrimSpace(os.Getenv("XDG_DATA_DIRS"))
	var dataDirs []string
	if rawDataDirs == "" {
		dataDirs = []string{"/usr/local/share", "/usr/share"}
	} else {
		for _, part := range splitEnvList(rawDataDirs) {
			if part != "" {
				dataDirs = append(dataDirs, part)
			}
		}
	}

	var appDirs []string
	if dataHome != "" {
		appDirs = append(appDirs, filepath.Join(dataHome, "applications"))
	}
	for _, d := range dataDirs {
		appDirs = append(appDirs, filepath.Join(d, "applications"))
	}
	if home != "" {
		appDirs = append(appDirs, filepath.Join(home, ".local", "share", "flatpak", "exports", "share", "applications"))
	}
	appDirs = append(appDirs,
		"/var/lib/flatpak/exports/share/applications",
		"/var/lib/snapd/desktop/applications",
	)

	var iconDirs []string
	if dataHome != "" {
		iconDirs = append(iconDirs, filepath.Join(dataHome, "icons"))
	}
	if home != "" {
		iconDirs = append(iconDirs,
			filepath.Join(home, ".icons"),
			filepath.Join(home, ".local", "share", "flatpak", "exports", "share", "icons"),
		)
	}
	iconDirs = append(iconDirs, "/var/lib/flatpak/exports/share/icons")
	for _, d := range dataDirs {
		iconDirs = append(iconDirs, filepath.Join(d, "icons"), filepath.Join(d, "pixmaps"))
	}
	iconDirs = append(iconDirs,
		"/usr/share/icons",
		"/usr/share/pixmaps",
		"/var/lib/snapd/desktop/icons",
	)

	pathDirs := splitEnvList(os.Getenv("PATH"))
	if len(pathDirs) == 0 {
		pathDirs = []string{"/usr/local/bin", "/usr/bin", "/bin"}
	}

	return Options{
		AppDirs:  dedupeStrings(appDirs),
		IconDirs: dedupeStrings(iconDirs),
		PathDirs: dedupeStrings(pathDirs),
	}
}

func splitEnvList(raw string) []string {
	if runtime.GOOS == "windows" && strings.Contains(raw, ";") {
		return filepath.SplitList(raw)
	}
	return strings.Split(raw, ":")
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// ExtractStrings converts a JSON-RPC "paths" argument ([]string or []any) into strings.
func ExtractStrings(raw any) []string {
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Discover reads all visible application .desktop entries under opts.AppDirs,
// deduplicated by Linux app key in AppDirs priority order.
func Discover(opts Options) []Entry {
	if len(opts.AppDirs) == 0 && len(opts.IconDirs) == 0 && len(opts.PathDirs) == 0 {
		opts = DefaultOptions()
	}
	seen := make(map[string]struct{})
	var out []Entry
	for _, dir := range opts.AppDirs {
		if dir == "" {
			continue
		}
		files, err := filepath.Glob(filepath.Join(dir, "*.desktop"))
		if err != nil {
			continue
		}
		sort.Strings(files)
		for _, file := range files {
			entry, ok := parseDesktopFile(file, opts.PathDirs)
			if !ok {
				continue
			}
			if _, exists := seen[entry.Key]; exists {
				continue
			}
			seen[entry.Key] = struct{}{}
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		li := strings.ToLower(out[i].Name)
		lj := strings.ToLower(out[j].Name)
		if li != lj {
			return li < lj
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// InstalledApps returns installed desktop apps in the JSON shape expected by Control.
func InstalledApps(opts Options) []any {
	entries := Discover(opts)
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		item := map[string]any{
			"name":     e.Name,
			"identity": e.Identity,
			"path":     e.Path,
			"key":      e.Key,
		}
		out = append(out, item)
	}
	return out
}

// AppInfo resolves display names and base64-encoded PNG/SVG icons for requested identities/paths.
func AppInfo(identities []string, opts Options) []any {
	if len(opts.AppDirs) == 0 && len(opts.IconDirs) == 0 && len(opts.PathDirs) == 0 {
		opts = DefaultOptions()
	}
	if len(identities) == 0 {
		return []any{}
	}
	entries := Discover(opts)
	byKey := make(map[string]Entry, len(entries))
	byBase := make(map[string]Entry)
	for _, e := range entries {
		byKey[e.Key] = e
		if !apps.SandboxIdentity(e.Identity) {
			b := strings.ToLower(path.Base(filepath.ToSlash(e.Path)))
			if b != "" {
				if _, exists := byBase[b]; !exists {
					byBase[b] = e
				}
			}
		}
	}

	out := make([]any, 0, len(identities))
	for _, raw := range identities {
		if raw == "" {
			continue
		}
		key := apps.AppKeyWith(raw, apppath.Linux)
		entry, found := byKey[key]
		if !found && !apps.SandboxIdentity(raw) {
			b := strings.ToLower(path.Base(filepath.ToSlash(raw)))
			if byB, ok := byBase[b]; ok {
				entry = byB
				found = true
			}
		}
		name := fallbackDisplayName(raw)
		var iconB64 string
		if found {
			if entry.Name != "" {
				name = entry.Name
			}
			if entry.Icon != "" {
				iconB64 = loadIconBase64(entry.Icon, opts.IconDirs)
			}
		}
		item := map[string]any{
			"identity": raw,
			"path":     raw,
			"name":     name,
		}
		if iconB64 != "" {
			item["icon"] = iconB64
		}
		out = append(out, item)
	}
	return out
}

func fallbackDisplayName(identity string) string {
	for _, p := range []string{"flatpak:", "snap:", "appimage:"} {
		if strings.HasPrefix(identity, p) {
			rest := strings.TrimPrefix(identity, p)
			if p == "flatpak:" {
				if idx := strings.LastIndex(rest, "."); idx >= 0 && idx+1 < len(rest) {
					return rest[idx+1:]
				}
			}
			return rest
		}
	}
	s := filepath.ToSlash(identity)
	b := path.Base(s)
	if b == "." || b == "/" || b == "" {
		return identity
	}
	return b
}

func parseDesktopFile(filePath string, pathDirs []string) (Entry, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return Entry{}, false
	}
	defer f.Close()

	var (
		inEntry   bool
		seenEntry bool
		entryType string
		name      string
		execLine  string
		icon      string
		hidden    bool
		noDisplay bool
		xFlatpak  string
		xSnapInst string
		tryExec   string
	)

	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 256*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if line == "[Desktop Entry]" {
				inEntry = true
				seenEntry = true
			} else if seenEntry {
				// Ignore [Desktop Action ...] or later sections completely.
				break
			} else {
				inEntry = false
			}
			continue
		}
		if !inEntry {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Type":
			if entryType == "" {
				entryType = v
			}
		case "Name":
			if name == "" {
				name = v
			}
		case "Exec":
			if execLine == "" {
				execLine = v
			}
		case "TryExec":
			if tryExec == "" {
				tryExec = v
			}
		case "Icon":
			if icon == "" {
				icon = v
			}
		case "Hidden":
			if strings.EqualFold(v, "true") {
				hidden = true
			}
		case "NoDisplay":
			if strings.EqualFold(v, "true") {
				noDisplay = true
			}
		case "X-Flatpak":
			if xFlatpak == "" {
				xFlatpak = v
			}
		case "X-SnapInstanceName":
			if xSnapInst == "" {
				xSnapInst = v
			}
		}
	}

	if hidden || noDisplay || name == "" || execLine == "" {
		return Entry{}, false
	}
	if entryType != "" && entryType != "Application" {
		return Entry{}, false
	}

	tokens := ParseExec(execLine)
	if len(tokens) == 0 {
		return Entry{}, false
	}

	identity, resolvedPath := deriveIdentity(filePath, tokens, xFlatpak, xSnapInst, pathDirs)
	if identity == "" {
		return Entry{}, false
	}
	if resolvedPath == "" {
		resolvedPath = identity
	}

	return Entry{
		Name:     name,
		Identity: identity,
		Path:     resolvedPath,
		Key:      apps.AppKeyWith(identity, apppath.Linux),
		Icon:     icon,
	}, true
}

// ParseExec tokenizes and unquotes a freedesktop Desktop Entry Exec line
// without invoking a shell, stripping % field codes and leading env wrappers.
func ParseExec(raw string) []string {
	var tokens []string
	var cur strings.Builder
	inToken := false
	inQuotes := false

	flush := func() {
		if inToken {
			s := stripFieldCodes(cur.String())
			if s != "" {
				tokens = append(tokens, s)
			}
			cur.Reset()
			inToken = false
		}
	}

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inQuotes {
			if c == '\\' && i+1 < len(raw) {
				i++
				cur.WriteByte(raw[i])
				continue
			}
			if c == '"' {
				inQuotes = false
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '"' {
			inQuotes = true
			inToken = true
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		if c == '\\' && i+1 < len(raw) {
			i++
			cur.WriteByte(raw[i])
			inToken = true
			continue
		}
		cur.WriteByte(c)
		inToken = true
	}
	flush()
	return stripEnvWrapper(tokens)
}

func stripFieldCodes(tok string) string {
	// Skip standalone field code tokens like %f, %F, %u, %U, %d, %D, %n, %N, %i, %c, %k, %v, %m.
	if len(tok) == 2 && tok[0] == '%' && tok[1] != '%' {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(tok); i++ {
		if tok[i] == '%' && i+1 < len(tok) {
			next := tok[i+1]
			if next == '%' {
				b.WriteByte('%')
				i++
				continue
			}
			if strings.ContainsRune("fFuUdDnNickvm", rune(next)) {
				i++
				continue
			}
		}
		b.WriteByte(tok[i])
	}
	return b.String()
}

func stripEnvWrapper(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	i := 0
	// Skip leading env binary and its VAR=VAL / short flags.
	base := path.Base(filepath.ToSlash(tokens[0]))
	if base == "env" {
		i++
		for i < len(tokens) {
			tok := tokens[i]
			if tok == "--" {
				i++
				break
			}
			if strings.HasPrefix(tok, "-") {
				if tok == "-u" || tok == "-C" || tok == "-S" {
					i += 2
				} else {
					i++
				}
				continue
			}
			if isEnvAssignment(tok) {
				i++
				continue
			}
			break
		}
	} else {
		for i < len(tokens) && isEnvAssignment(tokens[i]) {
			i++
		}
	}
	if i >= len(tokens) {
		return nil
	}
	return tokens[i:]
}

func isEnvAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	name := tok[:eq]
	for idx, r := range name {
		if idx == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func deriveIdentity(filePath string, tokens []string, xFlatpak, xSnapInst string, pathDirs []string) (string, string) {
	if xFlatpak != "" {
		return "flatpak:" + xFlatpak, "flatpak:" + xFlatpak
	}
	if xSnapInst != "" {
		snapName := snapPackageName(xSnapInst)
		return "snap:" + snapName, "snap:" + snapName
	}

	slashFile := filepath.ToSlash(filePath)
	if strings.Contains(slashFile, "/flatpak/exports/share/applications/") {
		appID := strings.TrimSuffix(path.Base(slashFile), ".desktop")
		if appID != "" && !strings.Contains(appID, "/") {
			return "flatpak:" + appID, "flatpak:" + appID
		}
	}
	if strings.Contains(slashFile, "/snapd/desktop/applications/") {
		base := strings.TrimSuffix(path.Base(slashFile), ".desktop")
		if snapName, _, ok := strings.Cut(base, "_"); ok && snapName != "" {
			return "snap:" + snapName, "snap:" + snapName
		}
	}

	cmd := filepath.ToSlash(tokens[0])
	base := path.Base(cmd)

	if base == "flatpak" {
		if appID := parseFlatpakRunAppID(tokens[1:]); appID != "" {
			return "flatpak:" + appID, "flatpak:" + appID
		}
	}
	if strings.HasPrefix(cmd, "/snap/bin/") || strings.HasPrefix(cmd, "/var/lib/snapd/snap/bin/") {
		snapName := snapPackageName(base)
		if snapName != "" {
			return "snap:" + snapName, resolveExecPath(cmd, pathDirs)
		}
	}
	if strings.HasPrefix(cmd, "/snap/") {
		parts := strings.Split(cmd, "/")
		if len(parts) > 3 && parts[2] != "" && parts[2] != "bin" {
			return "snap:" + parts[2], apppath.Normalize(cmd, apppath.Linux)
		}
	}
	if base == "snap" && len(tokens) >= 3 && tokens[1] == "run" {
		for _, tok := range tokens[2:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			snapName := snapPackageName(tok)
			if snapName != "" {
				return "snap:" + snapName, "snap:" + snapName
			}
			break
		}
	}

	resolved := resolveExecPath(cmd, pathDirs)
	norm := apppath.Normalize(resolved, apppath.Linux)
	return norm, norm
}

func snapPackageName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if pkg, _, ok := strings.Cut(s, "."); ok && pkg != "" {
		return pkg
	}
	return s
}

func parseFlatpakRunAppID(args []string) string {
	sawRun := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !sawRun {
			if a == "run" {
				sawRun = true
			} else if strings.HasPrefix(a, "-") {
				continue
			}
			continue
		}
		if a == "--" {
			if i+1 < len(args) {
				return cleanFlatpakRef(args[i+1])
			}
			return ""
		}
		if strings.HasPrefix(a, "-") {
			// Flags taking a separate argument when '=' is absent.
			if !strings.Contains(a, "=") && (a == "--branch" || a == "--arch" || a == "--command" || a == "--file-forwarding") {
				i++
			}
			continue
		}
		return cleanFlatpakRef(a)
	}
	return ""
}

func cleanFlatpakRef(s string) string {
	// Handle ref/app/x86_64/stable style or plain org.mozilla.Firefox.
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '/'); idx > 0 {
		s = s[:idx]
	}
	return s
}

func resolveExecPath(cmd string, pathDirs []string) string {
	if strings.Contains(cmd, "/") {
		return path.Clean(cmd)
	}
	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, cmd)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		return path.Clean(filepath.ToSlash(candidate))
	}
	return cmd
}

func loadIconBase64(iconName string, iconDirs []string) string {
	iconName = strings.TrimSpace(iconName)
	if iconName == "" {
		return ""
	}
	var candidates []string
	if strings.Contains(iconName, "/") || filepath.IsAbs(iconName) {
		candidates = appendPathVariants(candidates, iconName)
	} else {
		themes := []string{"hicolor", "Adwaita", "Papirus", "breeze", "gnome", "elementary"}
		sizes := []string{"48x48", "32x32", "64x64", "24x24", "128x128", "256x256", "scalable"}
		shortSizes := []string{"48", "32", "64", "24", "128", "scalable"}
		for _, dir := range iconDirs {
			if dir == "" {
				continue
			}
			for _, theme := range themes {
				for _, sz := range sizes {
					candidates = appendPathVariants(candidates, filepath.Join(dir, theme, sz, "apps", iconName))
				}
				for _, sz := range shortSizes {
					candidates = appendPathVariants(candidates, filepath.Join(dir, theme, "apps", sz, iconName))
				}
			}
			candidates = appendPathVariants(candidates, filepath.Join(dir, iconName))
		}
	}
	for _, p := range candidates {
		if b := readBoundedIcon(p); len(b) > 0 {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return ""
}

func appendPathVariants(dst []string, base string) []string {
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".svg") {
		return append(dst, base)
	}
	return append(dst, base+".png", base+".svg")
}

func readBoundedIcon(file string) []byte {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() || info.Size() > maxIconBytes {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, maxIconBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxIconBytes {
		return nil
	}
	return b
}
