//go:build windows

package lifecycle

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// raiseServicePriority gives Net Switch's services CPU ahead of ordinary apps,
// as the Linux units do with Nice=-5: routing, and the lease and health checks
// that keep it on, must keep running while the apps they serve are busy. On
// 2026-11-23 a native Android build (15 compilers on 12 threads) starved the
// services at Normal priority until their few-second deadlines failed. A child
// process does not inherit Above Normal, so each process calls this itself.
// An explicit class set by an administrator is kept.
func raiseServicePriority() (string, error) {
	process := windows.CurrentProcess()
	class, err := windows.GetPriorityClass(process)
	if err != nil {
		return "", err
	}
	if class != windows.NORMAL_PRIORITY_CLASS {
		return fmt.Sprintf("process priority: keeping explicit class 0x%x", class), nil
	}
	if err := windows.SetPriorityClass(process, windows.ABOVE_NORMAL_PRIORITY_CLASS); err != nil {
		return "", err
	}
	if class, err = windows.GetPriorityClass(process); err != nil {
		return "", err
	}
	if class != windows.ABOVE_NORMAL_PRIORITY_CLASS {
		return "", fmt.Errorf("priority class is 0x%x after raising it to above normal", class)
	}
	return "process priority: above normal", nil
}
