package lifecycle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stoppedNativeThreads(taskDir string) (bool, string, error) {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return false, "", err
	}
	if len(entries) == 0 {
		return false, "", fmt.Errorf("no threads in %s", taskDir)
	}
	all := true
	var states []string
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(taskDir, entry.Name(), "stat"))
		if err != nil {
			// An exiting thread can disappear while the group is stopping;
			// require a fresh complete enumeration instead of crediting it.
			if os.IsNotExist(err) {
				return false, entry.Name() + " vanished", nil
			}
			return false, "", err
		}
		// comm is parenthesized and can itself contain spaces and ')'.
		end := strings.LastIndexByte(string(b), ')')
		if end < 0 || len(b) <= end+3 || b[end+1] != ' ' || b[end+3] != ' ' {
			return false, "", fmt.Errorf("malformed stat for thread %s: %q", entry.Name(), b)
		}
		state := b[end+2]
		states = append(states, fmt.Sprintf("%s=%c", entry.Name(), state))
		all = all && state == 'T'
	}
	if all {
		// A thread may have spawned another while the first enumeration was
		// being stopped. Once this complete set is stopped it cannot grow.
		again, err := os.ReadDir(taskDir)
		if err != nil {
			return false, "", err
		}
		if len(again) != len(entries) {
			return false, "thread set changed", nil
		}
		for i := range entries {
			if entries[i].Name() != again[i].Name() {
				return false, "thread set changed", nil
			}
		}
	}
	return all, strings.Join(states, " "), nil
}

func TestNativeStallStoppedThreadsRequiresEveryThread(t *testing.T) {
	dir := t.TempDir()
	for _, tid := range []string{"100", "101"} {
		if err := os.Mkdir(filepath.Join(dir, tid), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(tid, state string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, tid, "stat"), []byte(tid+" (worker ) name) "+state+" 1 2 3\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("100", "T")
	for _, state := range []string{"R", "S", "D", "Z", "t", "T"} {
		write("101", state)
		got, detail, err := stoppedNativeThreads(dir)
		if err != nil || got != (state == "T") {
			t.Fatal(state, got, detail, err)
		}
	}
}
