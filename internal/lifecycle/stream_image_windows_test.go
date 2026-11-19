//go:build windows

package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	win "github.com/kekawia/net-switch/internal/platform/windows"
)

func TestInstalledStreamWorkerSelection(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Directory: dir}
	engine := filepath.Join(dir, "netswitch-engine.exe")
	stream := filepath.Join(dir, "netswitch-worker.exe")
	check := func(want string) {
		t.Helper()
		s := nativePlatform(cfg, func(string) {}).(*win.System)
		if s.StreamExecutable != want || s.Workers.Executable != engine || s.EnginePath != engine {
			t.Fatalf("stream %q, one-shot %q, engine %q", s.StreamExecutable, s.Workers.Executable, s.EnginePath)
		}
	}
	check(engine)
	if err := os.WriteFile(stream, nil, 0600); err != nil {
		t.Fatal(err)
	}
	check(stream)
}
