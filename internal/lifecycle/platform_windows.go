package lifecycle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kekawia/net-switch/internal/platform"
	win "github.com/kekawia/net-switch/internal/platform/windows"
	"github.com/kekawia/net-switch/internal/platform/worker"
)

func nativePlatform(c Config, log func(string)) platform.System {
	engine := filepath.Join(c.Directory, "netswitch-engine.exe")
	executable := filepath.Join(c.Directory, "netswitch-worker.exe")
	// Older version directories supplied the same worker modes in the engine.
	if _, err := os.Lstat(executable); os.IsNotExist(err) {
		executable = engine
	}
	return &win.System{
		Workers:          worker.Supervisor{Executable: engine, Log: func(err error) { log(err.Error()) }},
		StreamExecutable: executable, EnginePath: engine, Root: c.Directory, UserDir: c.Data, MachineDir: c.Data,
	}
}
func Worker(args []string) int { return win.Run(args) }
func DesktopCall(ctx context.Context, operation string, args map[string]any) (any, error) {
	switch operation {
	case "app-info", "installed-apps":
		return win.Execute(operation, args)
	case "autostart":
		return desktopAutostart(nil)
	case "autostart-set":
		value, _ := args["on"].(bool)
		return desktopAutostart(&value)
	case "autostart-upgrade":
		return "unchanged", nil
	}
	return nil, fmt.Errorf("desktop operation %q refused", operation)
}
