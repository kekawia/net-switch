//go:build !windows

package lifecycle

import (
	"context"
	"errors"

	"github.com/AyoubAchour/net-switch/internal/control"
)

type MigrateProfilesResult struct{}

type MigrateOptions struct {
	AppDir   string
	StageDir string
	Version  string
	Owner    string
	Profile  string
	DataDir  string
	OutPath  string
}

type InstallVersionedOptions struct {
	AppDir       string
	StageDir     string
	Version      string
	Owner        string
	DataDir      string
	Mode         string
	OwnerBackend string
}

func MigrateProfiles(string, string, string, string) (MigrateProfilesResult, error) {
	return MigrateProfilesResult{}, errors.New("migrate-profiles is only supported on Windows")
}

func Migrate(context.Context, MigrateOptions) error {
	return errors.New("0.3.x migration is only supported on Windows")
}

func InstallVersioned(context.Context, InstallVersionedOptions) error {
	return errors.New("versioned Windows layout install is only supported on Windows")
}

func HardenInstallRootCommand(string) error {
	return errors.New("harden-root is only supported on Windows")
}

func StopInstalledDesktopProcesses(string) error {
	return nil
}

func runMigrationHealthCheck(context.Context, Config, *control.Core, *Remote, func(string)) {}
