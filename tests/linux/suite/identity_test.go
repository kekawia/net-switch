//go:build linux

package suite

import (
	"encoding/hex"
	"strings"
	"testing"
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
