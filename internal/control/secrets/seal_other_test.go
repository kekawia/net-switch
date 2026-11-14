//go:build !windows

package secrets

import (
	"os"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
)

func TestUnixSecretFilePermissions0600(t *testing.T) {
	dir := t.TempDir()
	st := New(dir, Options{})
	if _, err := st.Put("proxy-1", proxy.Credentials{Username: "u", Password: "p"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, p := range []string{st.File(), st.File() + ".bak"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("%s perm = %04o, want 0600", p, perm)
		}
	}
}
