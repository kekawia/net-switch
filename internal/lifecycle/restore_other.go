//go:build !windows

package lifecycle

import "errors"

func RestoreWindows(string) error {
	return errors.New("restore-windows is only supported on Windows")
}

func CleanupMachineDataCommand(string) error {
	return errors.New("cleanup-machine-data is only supported on Windows")
}

func WhoamiCommand(string, string) (Owner, error) {
	return Owner{}, errors.New("whoami is only supported on Windows")
}

func WriteInstallerError(string, error) {}

func setOwnerRunKey(string, string, bool) error {
	return nil
}
