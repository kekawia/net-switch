package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/updates"
)

// ParseCurrentMarker validates the single-line {app}\current marker ("app-X.Y.Z").
func ParseCurrentMarker(raw []byte) (string, error) {
	if len(raw) > 128 {
		return "", errors.New("current version marker exceeds maximum length")
	}
	value := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(value, "app-") || strings.ContainsAny(value, `/\:`) {
		return "", fmt.Errorf("invalid current version marker %q", value)
	}
	ver := strings.TrimPrefix(value, "app-")
	if updates.ParseVersion(ver) == nil || strings.HasPrefix(ver, "v") {
		return "", fmt.Errorf("invalid current version %q", value)
	}
	return value, nil
}

func isVersionedAppSubdir(name string) bool {
	if !strings.HasPrefix(strings.ToLower(name), "app-") {
		return false
	}
	ver := name[len("app-"):]
	return !strings.HasPrefix(strings.ToLower(ver), "v") && updates.ParseVersion(ver) != nil
}

func stableDesktopExecutable(exe string) string {
	return stableDesktopExecutableFor(exe, func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.Mode().IsRegular()
	})
}

func stableDesktopExecutableFor(exe string, regularFile func(string) bool) string {
	exe = filepath.Clean(exe)
	dir := filepath.Dir(exe)
	if !isVersionedAppSubdir(filepath.Base(dir)) {
		return exe
	}
	parent := filepath.Dir(dir)
	rootExe := filepath.Join(parent, filepath.Base(exe))
	marker := filepath.Join(parent, "current")
	if regularFile(marker) && regularFile(rootExe) {
		return rootExe
	}
	return exe
}

func synchronousLauncherInvocation(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		switch {
		case arg == "-version" || arg == "--version",
			arg == "-h" || arg == "--help" || arg == "-help",
			arg == "-autostart" || arg == "--autostart",
			strings.HasPrefix(arg, "-autostart="),
			strings.HasPrefix(arg, "--autostart="):
			return true
		}
	}
	return false
}
