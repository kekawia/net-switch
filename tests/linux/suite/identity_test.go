//go:build linux

package suite

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAppImageToolPinsAreComplete(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		tools := appImageTools[arch]
		if len(tools) != 2 {
			t.Fatalf("%s AppImage tools = %d, want 2", arch, len(tools))
		}
		for _, name := range []string{"appimagetool", "runtime"} {
			pin, ok := tools[name]
			if !ok {
				t.Fatalf("%s missing %s pin", arch, name)
			}
			if !strings.HasPrefix(pin.URL, "https://") || pin.Size <= 0 || len(pin.SHA256) != 64 {
				t.Fatalf("%s/%s invalid pin: %+v", arch, name, pin)
			}
			if _, err := hex.DecodeString(pin.SHA256); err != nil {
				t.Fatalf("%s/%s invalid sha256 %q: %v", arch, name, pin.SHA256, err)
			}
		}
	}
}

func TestInstallSnapInputsWaitsForSeedBeforeOfflineConfig(t *testing.T) {
	t.Setenv("NSACCEPT_SNAP_CACHE", t.TempDir())
	var calls []string
	_, err := installSnapInputs(context.Background(), func(_ time.Duration, _ int, name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if call == "snap set system store.access=offline" {
			return "", errors.New("stop after offline config")
		}
		return "", nil
	}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "stop after offline config") {
		t.Fatalf("installSnapInputs error = %v, want stop after offline config", err)
	}
	want := []string{
		"snap wait system seed.loaded",
		"snap set system store.access=offline",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("snap calls = %v, want %v", calls, want)
	}
}
