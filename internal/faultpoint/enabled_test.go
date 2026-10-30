//go:build lifecycle_test

package faultpoint

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPausePublishesHitBeforeRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fault-before-read")
	if err := os.WriteFile(path, []byte("pause"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { Hit(dir, "before-read"); close(done) }()
	t.Cleanup(func() { os.Remove(path + ".consumed") })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "fault-hit.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pause never published its hit")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("pause returned before release")
	default:
	}
	// Hit reads the mode before publishing its hit, so release cannot race
	// that read even when the observer removes the file immediately.
	if err := os.Remove(path + ".consumed"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pause did not return after release")
	}
	Hit(dir, "before-read") // one shot, consumed arm cannot block again
}
