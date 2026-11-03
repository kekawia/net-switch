package lifecycle_test

import (
	"testing"
	"time"
)

type workerRef interface {
	id() uint32
	kind() string
	alive() bool
	suspend() error
	close()
}

func validWorkerArgs(args []string, enginePath string, samePath func(string, string) bool) bool {
	if len(args) == 3 && args[1] == "worker" && (args[2] == "network" || args[2] == "meters") {
		return true
	}
	return len(args) == 5 && args[1] == "worker" && args[2] == "outside" && args[3] == "--engine" && samePath(args[4], enginePath)
}

func runningWorkers(t *testing.T, parent uint32, directory string) []workerRef {
	t.Helper()
	var refs []workerRef
	wait(t, "three live worker streams", 15*time.Second, func() bool {
		for _, ref := range refs {
			ref.close()
		}
		refs = findWorkers(t, parent, directory)
		modes := map[string]bool{}
		for _, ref := range refs {
			modes[ref.kind()] = true
		}
		return modes["network"] && modes["meters"] && modes["outside"]
	})
	for _, ref := range refs {
		if !ref.alive() {
			t.Fatal("worker exited before fault injection")
		}
		t.Logf("live worker stream mode=%s pid=%d", ref.kind(), ref.id())
		t.Cleanup(ref.close)
	}
	return refs
}
func workersGone(t *testing.T, refs []workerRef, duration time.Duration) {
	t.Helper()
	wait(t, "owned workers exited", duration, func() bool {
		for _, ref := range refs {
			if ref.alive() {
				return false
			}
		}
		return true
	})
}
