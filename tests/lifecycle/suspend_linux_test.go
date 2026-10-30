package lifecycle_test

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func suspendAdapter(t *testing.T, pid uint32) {
	t.Helper()
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	// kill only queues the group stop. Every Go thread must have observed it
	// before the caller sends traffic intended to prove a frozen child.
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for {
		stopped, detail, err := stoppedNativeThreads(fmt.Sprintf("/proc/%d/task", pid))
		last = detail
		if err != nil {
			_ = unix.Kill(int(pid), unix.SIGCONT)
			t.Fatalf("observe SIGSTOP pid=%d: %v", pid, err)
		}
		if stopped {
			return
		}
		if time.Now().After(deadline) {
			_ = unix.Kill(int(pid), unix.SIGCONT)
			t.Fatalf("SIGSTOP pid=%d did not stop every thread within 5s: %s", pid, last)
		}
		time.Sleep(time.Millisecond)
	}
}
