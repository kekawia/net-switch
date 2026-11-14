package secrets

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
)

type recordingFiles struct {
	mu     sync.Mutex
	events []string
	data   map[string][]byte
}

func newRecordingFiles() *recordingFiles {
	return &recordingFiles{data: map[string][]byte{}}
}

func (r *recordingFiles) ReadFile(p string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "read:"+filepath.Base(p))
	b, ok := r.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (r *recordingFiles) WriteFile(p string, b []byte, _ fs.FileMode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "write:"+filepath.Base(p))
	r.data[p] = append([]byte(nil), b...)
	return nil
}

func (r *recordingFiles) Rename(a, b string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "rename:"+filepath.Base(b))
	r.data[b] = r.data[a]
	delete(r.data, a)
	return nil
}

func (r *recordingFiles) Remove(p string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "remove:"+filepath.Base(p))
	delete(r.data, p)
	return nil
}

func TestStoreLazyNoIOUntilProxyCredentialsUsed(t *testing.T) {
	rf := newRecordingFiles()
	st := New(t.TempDir(), Options{Files: rf})

	out, err := st.Resolve(nil)
	if err != nil || out != nil {
		t.Fatalf("Resolve(nil) = (%v, %v), want (nil, nil)", out, err)
	}
	out, err = st.Resolve([]string{"", ""})
	if err != nil || out != nil {
		t.Fatalf("Resolve(empty refs) = (%v, %v), want (nil, nil)", out, err)
	}
	if len(rf.events) != 0 {
		t.Fatalf("expected zero filesystem operations when no proxy secrets exist, got %v", rf.events)
	}
}

func TestStoreRoundTripRevisionMonotonicityBackupAndZeroLeakInvariants(t *testing.T) {
	dir := t.TempDir()
	st := New(dir, Options{})

	var (
		user = "mock-proxy-acct"
		pass = "fixture-" + strings.Repeat("z", 14)
	)
	rev1, err := st.Put("proxy-nl", proxy.Credentials{Username: user, Password: pass})
	if err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	if rev1 != 1 {
		t.Fatalf("rev1 = %d, want 1", rev1)
	}

	got, gotRev, ok, err := st.Get("proxy-nl")
	if err != nil || !ok || gotRev != 1 {
		t.Fatalf("Get #1 = (ok=%v rev=%d err=%v)", ok, gotRev, err)
	}
	if got.Username != user || got.Password != pass {
		t.Fatalf("round-trip mismatch: got (%q, %q)", got.Username, got.Password)
	}

	// Updating credentials must strictly increment CredentialsRev and change policy.Hash
	// without placing any secret material in policy.Config or serialized Line JSON.
	rev2, err := st.Put("proxy-nl", proxy.Credentials{Username: user, Password: pass + "-rotated"})
	if err != nil {
		t.Fatalf("Put #2: %v", err)
	}
	if rev2 <= rev1 {
		t.Fatalf("rev2 = %d, want > %d", rev2, rev1)
	}

	cfg1 := policy.Config{
		Lines: []platform.Line{
			{ID: "cable"},
			{ID: "proxy-nl", Proxy: &platform.ProxyLine{
				Protocol:       "socks5",
				Server:         "198.51.100.20:1080",
				Carrier:        "cable",
				CredentialsRef: "proxy-nl",
				CredentialsRev: rev1,
			}},
		},
	}
	cfg2 := cfg1
	cfg2.Lines = append([]platform.Line(nil), cfg1.Lines...)
	proxyCopy := *cfg1.Lines[1].Proxy
	proxyCopy.CredentialsRev = rev2
	cfg2.Lines[1].Proxy = &proxyCopy

	h1 := policy.Hash(cfg1)
	h2 := policy.Hash(cfg2)
	if h1 == h2 {
		t.Fatalf("policy.Hash did not change when CredentialsRev rotated (%s)", h1)
	}
	if _, err := policy.Compile(policy.Revision{N: 1, Hash: h1, Config: cfg1}); err != nil {
		t.Fatalf("Compile cfg1: %v", err)
	}
	if _, err := policy.Compile(policy.Revision{N: 2, Hash: h2, Config: cfg2}); err != nil {
		t.Fatalf("Compile cfg2: %v", err)
	}
	cfgJSON, err := json.Marshal(cfg2)
	if err != nil {
		t.Fatalf("marshal policy.Config: %v", err)
	}
	for _, forbidden := range []string{
		user,
		pass,
		base64.StdEncoding.EncodeToString([]byte(user)),
		base64.StdEncoding.EncodeToString([]byte(pass)),
	} {
		if strings.Contains(string(cfgJSON), forbidden) {
			t.Fatalf("policy.Config JSON leaked secret material %q: %s", forbidden, string(cfgJSON))
		}
	}

	// Delete + re-Put on the same ref across a fresh Store instance must keep monotonic Rev > rev2.
	if err := st.Delete("proxy-nl"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	reloaded := New(dir, Options{})
	if _, _, exists, err := reloaded.Get("proxy-nl"); err != nil || exists {
		t.Fatalf("expected deleted entry to be absent: exists=%v err=%v", exists, err)
	}
	rev3, err := reloaded.Put("proxy-nl", proxy.Credentials{Username: user, Password: pass})
	if err != nil {
		t.Fatalf("Put #3 after delete: %v", err)
	}
	if rev3 <= rev2 {
		t.Fatalf("rev3 = %d after delete+recreate, want > %d", rev3, rev2)
	}

	// Corrupting primary proxy-secrets.json must recover from .bak cleanly.
	if err := os.WriteFile(reloaded.File(), []byte("{corrupt-json"), 0600); err != nil {
		t.Fatalf("corrupt primary: %v", err)
	}
	recovered := New(dir, Options{})
	resolved, err := recovered.Resolve([]string{"proxy-nl", "missing-ref"})
	if err != nil {
		t.Fatalf("Resolve from backup: %v", err)
	}
	if len(resolved) != 1 || resolved["proxy-nl"].Password != pass {
		t.Fatalf("unexpected backup Resolve result: len=%d", len(resolved))
	}
}
