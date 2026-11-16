//go:build windows

package secrets

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kekawia/net-switch/internal/engine/proxy"
	"golang.org/x/sys/windows"
)

func TestWindowsDPAPIFlagsNoPlaintextAndEntropyBinding(t *testing.T) {
	if dpapiProtectFlags&windows.CRYPTPROTECT_LOCAL_MACHINE != 0 {
		t.Fatalf("dpapiProtectFlags = %#x MUST NOT set CRYPTPROTECT_LOCAL_MACHINE", dpapiProtectFlags)
	}
	if dpapiProtectFlags&windows.CRYPTPROTECT_UI_FORBIDDEN == 0 {
		t.Fatalf("dpapiProtectFlags = %#x MUST set CRYPTPROTECT_UI_FORBIDDEN", dpapiProtectFlags)
	}

	dir := t.TempDir()
	st := New(dir, Options{})
	const (
		user = "win-dpapi-user"
		pass = "win-dpapi-top-secret-password"
	)
	if _, err := st.Put("proxy-a", proxy.Credentials{Username: user, Password: pass}); err != nil {
		t.Fatalf("Put proxy-a: %v", err)
	}

	rawDisk, err := os.ReadFile(st.File())
	if err != nil {
		t.Fatalf("ReadFile proxy-secrets.json: %v", err)
	}
	diskStr := string(rawDisk)
	if !strings.Contains(diskStr, `"scheme": "dpapi-v1"`) {
		t.Fatalf("expected dpapi-v1 scheme on Windows, got: %s", diskStr)
	}
	for _, forbidden := range []string{
		user,
		pass,
		base64.StdEncoding.EncodeToString([]byte(user)),
		base64.StdEncoding.EncodeToString([]byte(pass)),
	} {
		if strings.Contains(diskStr, forbidden) {
			t.Fatalf("proxy-secrets.json on Windows leaked %q", forbidden)
		}
	}

	// Copying proxy-a's ciphertext onto proxy-b must fail CryptUnprotectData
	// because optionalEntropy binds each ciphertext to its CredentialsRef.
	var parsed filePayload
	if err := json.Unmarshal(rawDisk, &parsed); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	parsed.Entries["proxy-b"] = parsed.Entries["proxy-a"]
	tampered, _ := json.Marshal(parsed)
	if err := os.WriteFile(st.File(), tampered, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	_ = os.WriteFile(st.File()+".bak", tampered, 0600)

	st2 := New(dir, Options{})
	if _, _, _, err := st2.Get("proxy-b"); err == nil {
		t.Fatal("expected swapped-ref DPAPI ciphertext to fail decryption")
	}
}
