package lifecycle_test

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestUsageSharingViolationOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		sharing bool
	}{
		{"success", nil, false},
		{"sharing", syscall.Errno(32), true},
		{"wrapped-sharing", &os.PathError{Op: "open", Path: "usage.json", Err: syscall.Errno(32)}, true},
		{"missing", os.ErrNotExist, false},
		{"permission", os.ErrPermission, false},
		{"access-denied", syscall.Errno(5), false},
		{"lock-violation", syscall.Errno(33), false},
		{"same-text", errors.New("The process cannot access the file because it is being used by another process."), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := usageSharingViolation(tc.err), tc.sharing && runtime.GOOS == "windows"; got != want {
				t.Fatalf("retry=%t, want %t for %v", got, want, tc.err)
			}
		})
	}
}
