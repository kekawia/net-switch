package control

import (
	"errors"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// A failed startup read is never permission to publish empty history. Windows
// replacement handles can briefly exclude readers; retry only those conflicts.
func readUsageHistory(o Options) ([]byte, error) {
	sleep := o.IO.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for attempt := 0; ; attempt++ {
		b, err := o.IO.Files.ReadFile(filepath.Join(o.UserDir, "usage.json"))
		sharing := runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(33)))
		if !sharing || attempt == 10 {
			return b, err
		}
		sleep(20 * time.Millisecond)
	}
}
