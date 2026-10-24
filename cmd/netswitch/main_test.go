package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRootIsExecutableFolderEvenFromAnotherDirectory(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	root, err := applicationRoot("", exe)
	if err != nil || root != filepath.Dir(exe) {
		t.Fatalf("default root %s: %v", root, err)
	}
	cwd, _ := os.Getwd()
	root, err = applicationRoot("override", exe)
	if err != nil || root != filepath.Join(cwd, "override") {
		t.Fatalf("override root %s: %v", root, err)
	}
}

// The product netswitch started by hand explains itself and starts nothing:
// Control runs only as the installed service. The sing-box launcher lives in
// the control_compat build alone, so this build has no path to an engine.
func TestProductBuildHasNoDesktopLauncher(t *testing.T) {
	if compatibilityLauncher {
		t.Skip("control_compat build carries the parity launcher")
	}
	defer func(args []string) { os.Args = args }(os.Args)
	os.Args = []string{"netswitch"}
	err := run()
	if err == nil || !strings.Contains(err.Error(), "netswitch service") || !strings.Contains(err.Error(), "installed Net Switch service") {
		t.Fatal("bare start did not explain the service", err)
	}
	os.Args = []string{"netswitch", "--dev-proxy", "--engine-executable", "sing-box.exe"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "netswitch service") {
		t.Fatal("launcher flags were accepted by the product build", err)
	}
	os.Args = []string{"netswitch", "-version"}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestStartupLeavesProtectedMachineCreationAndRecoveryToWorker(t *testing.T) {
	base := t.TempDir()
	user, machine := filepath.Join(base, "user"), filepath.Join(base, "machine")
	if err := prepareDataDirectories(user, machine, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(machine); !os.IsNotExist(err) {
		t.Fatal("startup recreated the protected machine folder before migration recovery", err)
	}
	if _, err := os.Stat(user); err != nil {
		t.Fatal(err)
	}
	if err := prepareDataDirectories(user, machine, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(machine); err != nil {
		t.Fatal("development data directory missing", err)
	}
}
