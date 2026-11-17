//go:build !windows

package lifecycle

import (
	"context"
	"errors"
	"github.com/kekawia/net-switch/internal/control"

	"github.com/kekawia/net-switch/internal/updates"
)

func newControlUpdater(context.Context, Config, func(string)) updates.Backend { return nil }
func recoverPendingUpdate(context.Context, string, func(string))              {}
func awaitControlUpdate(context.Context, string, func(), func(string)) (bool, error) {
	return false, nil
}
func runUpdateHealthCheck(context.Context, Config, *control.Core, *Remote, func(string)) bool {
	return false
}
func readActiveUpdateSnapshot(string, string) (bool, error) {
	return false, errors.New("Windows update snapshot is unavailable")
}
func authorizeUpdateRestart(string, string) error {
	return errors.New("Windows update restart is unavailable")
}
func ApplyUpdate(context.Context, string, string) error {
	return errors.New("update with your Linux package manager")
}
func KeepUpdateInstaller(context.Context, string, string, string, string, string) error {
	return errors.New("kept Windows installers are unsupported on this platform")
}
