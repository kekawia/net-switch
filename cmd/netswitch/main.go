// Command netswitch hosts the 1.0 Control service and its platform workers.
// The 0.3.x compatibility launcher (an elevated desktop Control over sing-box)
// exists only in the control_compat build the parity workflow drives; see
// launcher_compat.go. The product build cannot start sing-box.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "service" {
		if err := lifecycle.ServiceCommand(service.Control, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		os.Exit(win.Run(os.Args[2:]))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepareDataDirectories(user, machine string, protectMachine bool) error {
	if err := os.MkdirAll(user, 0700); err != nil {
		return err
	}
	// ProtectDirectory owns protected-at-creation security and recovery. An
	// eager MkdirAll here both reopens the legacy ACL window and replaces the
	// missing root identity after an interrupted quarantine, blocking resume.
	if !protectMachine {
		return os.MkdirAll(machine, 0700)
	}
	return nil
}
func applicationRoot(override, executable string) (string, error) {
	if override == "" {
		return filepath.Dir(executable), nil
	}
	return filepath.Abs(override)
}
