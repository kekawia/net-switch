package lifecycle

import (
	"context"
	"errors"

	"github.com/kekawia/net-switch/internal/control"
)

func packageCommand([]string) error { return errors.New("package commands require Linux") }

func checkManualInstall() error { return nil }

func stopInstalledControl(ctx context.Context, _ string, c *control.Core) error {
	return c.ShutdownForService(ctx)
}
