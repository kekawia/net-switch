package lifecycle

import (
	"os"
	"path/filepath"

	"github.com/kekawia/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
)

func restartDesktopProcess(show bool) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable = stableDesktopExecutable(executable)
	if err := wintrust.Path(executable, false); err != nil {
		return err
	}
	args := []string{executable, "--resume"}
	if !show {
		args = append(args, "--background")
	}
	return spawnDetachedProcess(executable, args, filepath.Dir(executable), windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_PROCESS_GROUP)
}
