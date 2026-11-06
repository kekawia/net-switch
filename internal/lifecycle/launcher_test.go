package lifecycle

import (
	"path/filepath"
	"testing"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/buildinfo"
)

func TestParseCurrentMarker(t *testing.T) {
	got, err := ParseCurrentMarker([]byte(" app-1.0.0\r\n"))
	if err != nil || got != "app-1.0.0" {
		t.Fatalf("ParseCurrentMarker valid: got %q, err=%v", got, err)
	}
	for _, bad := range []string{"", "1.0.0", "app-v1.0.0", "app-1.0", `app-1.0.0\..`, "app-1.0.0/extra", "other-1.0.0"} {
		if _, err := ParseCurrentMarker([]byte(bad)); err == nil {
			t.Fatalf("ParseCurrentMarker(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestStableDesktopExecutableResolution(t *testing.T) {
	appRoot := filepath.Join("C:", "Program Files", "Net Switch")
	versionedExe := filepath.Join(appRoot, "app-1.0.0", "netswitch-desktop.exe")
	rootExe := filepath.Join(appRoot, "netswitch-desktop.exe")
	marker := filepath.Join(appRoot, "current")

	present := map[string]bool{rootExe: true, marker: true}
	if got := stableDesktopExecutableFor(versionedExe, func(p string) bool { return present[p] }); got != rootExe {
		t.Fatalf("versioned desktop with root launcher: got %q, want %q", got, rootExe)
	}
	if got := stableDesktopExecutableFor(versionedExe, func(string) bool { return false }); got != filepath.Clean(versionedExe) {
		t.Fatalf("versioned desktop without root marker: got %q, want %q", got, filepath.Clean(versionedExe))
	}
	singleDirExe := filepath.Join(appRoot, "netswitch-desktop.exe")
	if got := stableDesktopExecutableFor(singleDirExe, func(p string) bool { return present[p] }); got != filepath.Clean(singleDirExe) {
		t.Fatalf("root desktop executable changed unexpectedly: got %q", got)
	}
}

func TestSynchronousLauncherInvocation(t *testing.T) {
	for _, args := range [][]string{
		{"-version"},
		{"--version"},
		{"-autostart", "status"},
		{"--autostart=on"},
		{"-h"},
	} {
		if !synchronousLauncherInvocation(args) {
			t.Fatalf("expected synchronous invocation for %v", args)
		}
	}
	for _, args := range [][]string{
		nil,
		{"--background"},
		{"-background"},
		{"--", "-version"},
	} {
		if synchronousLauncherInvocation(args) {
			t.Fatalf("expected detached invocation for %v", args)
		}
	}
}

func TestAppVersionUsesSemverBuildInfoOrManifestFallback(t *testing.T) {
	orig := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = orig })

	for _, raw := range []string{"", "dev", "ed3616a98aae7cd85f8db4223ff6b9d1e7f289ac", "1.0.0-rc1"} {
		buildinfo.Version = raw
		if got := assets.AppVersion(); got != "0.3.1" {
			t.Fatalf("buildinfo.Version=%q: got %q, want 0.3.1", raw, got)
		}
	}
	for raw, want := range map[string]string{
		"1.0.0":   "1.0.0",
		"v1.0.1":  "1.0.1",
		" 1.2.3 ": "1.2.3",
	} {
		buildinfo.Version = raw
		if got := assets.AppVersion(); got != want {
			t.Fatalf("buildinfo.Version=%q: got %q, want %q", raw, got, want)
		}
	}
}
