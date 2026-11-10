package wintrust

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHardenTreeSetsTrustedPermissionsAndRejectsHardLinks(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("setting Builtin\\Administrators ownership requires elevation")
	}
	root := filepath.Join(t.TempDir(), "app-1.0.0")
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "netswitch.exe")
	if err := os.WriteFile(exe, []byte("pe"), 0644); err != nil {
		t.Fatal(err)
	}
	ico := filepath.Join(root, "assets", "net-switch.ico")
	if err := os.WriteFile(ico, []byte("ico"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := HardenTree(root); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{root, exe, filepath.Join(root, "assets"), ico} {
		if err := Path(p, false); err != nil {
			t.Fatalf("Path(%s, false) failed after HardenTree: %v", p, err)
		}
	}

	link := filepath.Join(t.TempDir(), "hardlink.exe")
	if err := os.Link(exe, link); err != nil {
		t.Fatal(err)
	}
	if err := HardenTree(root); err == nil {
		t.Fatal("HardenTree accepted a file with multiple hard links")
	}
}
