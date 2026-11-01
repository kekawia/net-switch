package lifecycle_test

import (
	"github.com/AyoubAchour/net-switch/internal/service"
	"os"
	"path/filepath"
	"testing"
)

func installationTrust(t *testing.T, dir string) {
	root := filepath.Join(dir, "trust-case")
	candidate := filepath.Join(root, "bin")
	if err := os.MkdirAll(candidate, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitch-desktop", "netswitchctl"} {
		if err := os.WriteFile(filepath.Join(candidate, binary(name)), []byte("non-executed trust fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	engine := filepath.Join(candidate, binary("netswitch-engine"))
	if err := service.CheckInstallation(candidate); err != nil {
		t.Fatal("trusted installation precondition", err)
	}
	if err := os.Link(engine, filepath.Join(candidate, "engine-hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckInstallation(candidate); err != nil {
		t.Fatal("protected hardlinked installation refused", err)
	}
	for _, path := range []string{filepath.Join(candidate, binary("netswitch")), engine, root} {
		restore := writableInstallPath(t, path)
		err := service.CheckInstallation(candidate)
		restore()
		if err == nil {
			t.Fatal("non-admin writable executable or ancestor was accepted", path)
		}
	}
	if err := service.CheckInstallation(candidate); err != nil {
		t.Fatal("legitimate installation rejected after controls", err)
	}
}
