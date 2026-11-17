//go:build !windows

package lifecycle

import (
	"os"
	"os/exec"
)

func restartDesktopProcess(show bool) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"--resume"}
	if !show {
		args = append(args, "--background")
	}
	command := exec.Command(executable, args...)
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
