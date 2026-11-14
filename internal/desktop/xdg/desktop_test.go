package xdg

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestParseExecQuotesFieldCodesAndEnv(t *testing.T) {
	got := ParseExec(`/usr/bin/env FOO=bar "My App" --flag="val with \"quotes\"" %U %%done`)
	want := []string{"My App", "--flag=val with \"quotes\"", "%done"}
	if len(got) != len(want) {
		t.Fatalf("ParseExec len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDiscoverDesktopEntriesIdentitiesAndIcons(t *testing.T) {
	root := t.TempDir()
	userApps := filepath.Join(root, "user-apps")
	sysApps := filepath.Join(root, "sys-apps")
	flatpakApps := filepath.Join(root, "flatpak", "exports", "share", "applications")
	snapApps := filepath.Join(root, "snapd", "desktop", "applications")
	binDir := filepath.Join(root, "bin")
	iconDir := filepath.Join(root, "icons")

	for _, d := range []string{
		userApps,
		sysApps,
		flatpakApps,
		snapApps,
		binDir,
		filepath.Join(iconDir, "hicolor", "48x48", "apps"),
		filepath.Join(iconDir, "hicolor", "scalable", "apps"),
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	fakeTool := filepath.Join(binDir, "mytool")
	if err := os.WriteFile(fakeTool, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	pngBytes := []byte("\x89PNG\r\n\x1a\nfake-png-icon")
	svgBytes := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/></svg>`)
	if err := os.WriteFile(filepath.Join(iconDir, "hicolor", "48x48", "apps", "mytool.png"), pngBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(iconDir, "hicolor", "scalable", "apps", "org.mozilla.Firefox.svg"), svgBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Native app using bare binary name resolved via PathDirs + [Desktop Action] must NOT overwrite Name/Exec.
	if err := os.WriteFile(filepath.Join(userApps, "mytool.desktop"), []byte(`[Desktop Entry]
Type=Application
Name=My Tool
Exec=env DISPLAY=:0 mytool --start %F
Icon=mytool

[Desktop Action new-window]
Name=Wrong Action Name
Exec=/usr/bin/wrong
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Hidden / NoDisplay entries must be ignored.
	if err := os.WriteFile(filepath.Join(sysApps, "hidden.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Hidden\nExec=/bin/true\nNoDisplay=true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysApps, "hidden2.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Hidden2\nExec=/bin/true\nHidden=true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Flatpak app.
	if err := os.WriteFile(filepath.Join(flatpakApps, "org.mozilla.Firefox.desktop"), []byte(`[Desktop Entry]
Type=Application
Name=Firefox Flatpak
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox --file-forwarding org.mozilla.Firefox @@u %u @@
Icon=org.mozilla.Firefox
X-Flatpak=org.mozilla.Firefox
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Snap app.
	if err := os.WriteFile(filepath.Join(snapApps, "brave_brave.desktop"), []byte(`[Desktop Entry]
Type=Application
Name=Brave Browser
Exec=/snap/bin/brave %U
Icon=brave
`), 0644); err != nil {
		t.Fatal(err)
	}

	// Oversized icon (>512 KiB) must be omitted.
	bigIconPath := filepath.Join(iconDir, "too-big.png")
	if err := os.WriteFile(bigIconPath, bytes.Repeat([]byte("A"), maxIconBytes+10), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysApps, "bigicon.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Big Icon App\nExec=/opt/big/bigapp\nIcon="+bigIconPath+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		AppDirs:  []string{userApps, sysApps, flatpakApps, snapApps},
		IconDirs: []string{iconDir},
		PathDirs: []string{binDir},
	}

	discovered := Discover(opts)
	if len(discovered) != 4 {
		t.Fatalf("Discover len = %d, want 4: %+v", len(discovered), discovered)
	}

	byID := map[string]Entry{}
	for _, e := range discovered {
		byID[e.Identity] = e
	}

	toolPath := filepath.ToSlash(fakeTool)
	if toolEntry, ok := byID[toolPath]; !ok || toolEntry.Name != "My Tool" {
		t.Fatalf("native tool entry mismatch: %+v (byID=%+v)", toolEntry, byID)
	}
	if ff, ok := byID["flatpak:org.mozilla.Firefox"]; !ok || ff.Name != "Firefox Flatpak" || ff.Key != "flatpak:org.mozilla.Firefox" {
		t.Fatalf("flatpak entry mismatch: %+v", ff)
	}
	if br, ok := byID["snap:brave"]; !ok || br.Name != "Brave Browser" || br.Key != "snap:brave" {
		t.Fatalf("snap entry mismatch: %+v", br)
	}

	items := AppInfo(ExtractStrings([]any{toolPath, "flatpak:org.mozilla.Firefox", "/opt/big/bigapp"}), opts)
	if len(items) != 3 {
		t.Fatalf("AppInfo len = %d, want 3", len(items))
	}
	it0 := items[0].(map[string]any)
	raw0, _ := base64.StdEncoding.DecodeString(it0["icon"].(string))
	if !bytes.Equal(raw0, pngBytes) {
		t.Fatalf("mytool PNG icon mismatch: got %q", raw0)
	}
	it1 := items[1].(map[string]any)
	if it1["name"] != "Firefox Flatpak" || it1["identity"] != "flatpak:org.mozilla.Firefox" {
		t.Fatalf("firefox AppInfo mismatch: %+v", it1)
	}
	raw1, _ := base64.StdEncoding.DecodeString(it1["icon"].(string))
	if !bytes.Equal(raw1, svgBytes) {
		t.Fatalf("firefox SVG icon mismatch: got %q", raw1)
	}
	it2 := items[2].(map[string]any)
	if _, hasIcon := it2["icon"]; hasIcon {
		t.Fatalf("oversized icon should have been omitted, got %v", it2["icon"])
	}
}
