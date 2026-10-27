package lifecycle_test

import (
	"errors"
	"github.com/AyoubAchour/net-switch/internal/usage"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
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
		{"lock-violation", syscall.Errno(33), true},
		{"same-text", errors.New("The process cannot access the file because it is being used by another process."), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := usageSharingViolation(tc.err), tc.sharing && runtime.GOOS == "windows"; got != want {
				t.Fatalf("retry=%t, want %t for %v", got, want, tc.err)
			}
		})
	}
}

func TestUsagePollingRetriesAndKeepsLastGood(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows sharing violation")
	}
	want := map[string]usage.RoutedEntry{"app": {Up: 42}}
	reads := 0
	got, err := pollRoutedApps(time.Now().Add(time.Second), time.Millisecond, func() (map[string]usage.RoutedEntry, error) {
		reads++
		if reads == 1 {
			return nil, syscall.Errno(32)
		}
		return want, nil
	}, func(v map[string]usage.RoutedEntry) bool { return v["app"].Up == 42 })
	if err != nil || got["app"].Up != 42 || reads != 2 {
		t.Fatal("sharing conflict not retried", got, err, reads)
	}
	reads = 0
	got, err = pollRoutedApps(time.Now().Add(10*time.Millisecond), time.Millisecond, func() (map[string]usage.RoutedEntry, error) {
		reads++
		if reads == 1 {
			return want, nil
		}
		return map[string]usage.RoutedEntry{}, syscall.Errno(32)
	}, func(map[string]usage.RoutedEntry) bool { return false })
	if err == nil || got["app"].Up != 42 || reads < 2 {
		t.Fatal("timeout lost last good record", got, err, reads)
	}
}
