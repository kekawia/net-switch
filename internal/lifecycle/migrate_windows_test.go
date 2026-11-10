package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"golang.org/x/sys/windows"
)

func TestCanonicalSettingsSignatureAndProfileSelection(t *testing.T) {
	_, nonDefEmpty, _ := canonicalSettingsSignature([]byte(`{}`))
	if nonDefEmpty {
		t.Fatal("empty object must be treated as default settings")
	}

	// Legacy 0.3.0 settings and 0.3.2 line-based settings representing the same
	// Cable + Wi-Fi lines with different random line IDs must produce the same signature.
	legacy030 := []byte(`{"mainAlias":"Ethernet","secondAlias":"Wi-Fi","secondLabel":"Wi-Fi","secondKind":"wifi","cableApps":["C:\\Apps\\Game.exe"]}`)
	modern032 := []byte(`{"lines":[{"id":"a1b2c3d4","alias":"Ethernet","label":"Cable","kind":"wired","weight":1},{"id":"e5f60718","alias":"Wi-Fi","label":"Wi-Fi","kind":"wifi","weight":1}],"appLines":{"C:\\Apps\\Game.exe":"a1b2c3d4"}}`)
	different032 := []byte(`{"lines":[{"id":"99887766","alias":"USB","label":"Phone","kind":"phone","metered":true,"weight":1}],"appLines":{}}`)

	sig030, nonDef030, _ := canonicalSettingsSignature(legacy030)
	sig032, nonDef032, _ := canonicalSettingsSignature(modern032)
	sigDiff, nonDefDiff, _ := canonicalSettingsSignature(different032)

	if !nonDef030 || !nonDef032 || !nonDefDiff {
		t.Fatalf("expected non-default flags true: %t %t %t", nonDef030, nonDef032, nonDefDiff)
	}
	if sig030 != sig032 {
		t.Fatalf("equivalent 0.3.0 and 0.3.2 settings produced different signatures:\n0.3.0=%s\n0.3.2=%s", sig030, sig032)
	}
	if sig032 == sigDiff {
		t.Fatal("distinct line configurations must produce distinct signatures")
	}

	// One profile with custom settings + one profile with default settings => no conflict.
	conflict, selected := selectMigrationProfile("S-1-5-21-1-2-3-1002", []ProfileCandidate{
		{SID: "S-1-5-21-1-2-3-1001", HasData: true, NonDefault: true, signature: sig032},
		{SID: "S-1-5-21-1-2-3-1002", HasData: true, NonDefault: false, signature: ""},
	})
	if conflict || selected != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("expected non-conflicting selection of 1001, got conflict=%t selected=%q", conflict, selected)
	}

	// Two profiles with identical custom settings => no conflict, owner preferred.
	conflict, selected = selectMigrationProfile("S-1-5-21-1-2-3-1002", []ProfileCandidate{
		{SID: "S-1-5-21-1-2-3-1001", HasData: true, NonDefault: true, signature: sig030},
		{SID: "S-1-5-21-1-2-3-1002", HasData: true, NonDefault: true, signature: sig032},
	})
	if conflict || selected != "S-1-5-21-1-2-3-1002" {
		t.Fatalf("expected identical profiles not to conflict and prefer owner, got conflict=%t selected=%q", conflict, selected)
	}

	// Two profiles with differing custom settings => conflict=true, owner preselected.
	conflict, selected = selectMigrationProfile("S-1-5-21-1-2-3-1002", []ProfileCandidate{
		{SID: "S-1-5-21-1-2-3-1001", HasData: true, NonDefault: true, signature: sig032},
		{SID: "S-1-5-21-1-2-3-1002", HasData: true, NonDefault: true, signature: sigDiff},
	})
	if !conflict || selected != "S-1-5-21-1-2-3-1002" {
		t.Fatalf("expected conflict=true with owner preselected, got conflict=%t selected=%q", conflict, selected)
	}
}

// Once {app}\current names the new version, the machine store is the live 1.0
// store. A journal from that point on must be finished, never rolled back: a
// rollback deletes that store and the next attempt imports the old profile.
func TestMigrationRecoveryNeverRollsBackPastTheCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		prev MigrationJournal
		live bool
		want string
	}{
		{"no journal", MigrationJournal{}, false, "fresh"},
		{"stopped after the copy", MigrationJournal{Phase: "copied"}, false, "rollback"},
		{"services installed, not yet healthy", MigrationJournal{Phase: "installed"}, false, "rollback"},
		{"healthy, nothing published", MigrationJournal{Phase: "healthy"}, false, "rollback"},
		{"healthy, published, commit not yet journaled", MigrationJournal{Phase: "healthy"}, true, "rollback"},
		{"interrupted while removing 0.3.x", MigrationJournal{Phase: "committing"}, true, "finish"},
		{"interrupted commit, marker unreadable", MigrationJournal{Phase: "committing"}, false, "finish"},
		{"committed, a 0.3.x file could not be removed", MigrationJournal{Phase: "committed"}, true, "finish"},
		{"committed, then uninstalled and 0.3.x put back", MigrationJournal{Phase: "committed"}, false, "fresh"},
		{"upgrade interrupted on a live install", MigrationJournal{Phase: "installed", Upgrade: true}, true, "finish"},
		{"upgrade journal left by a removed install", MigrationJournal{Phase: "installed", Upgrade: true}, false, "fresh"},
	} {
		if got := migrationRecovery(tc.prev, tc.live); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestVerifyStageChecksumsAndTamperRejection(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"netswitch.exe":     []byte("binary-a"),
		"sub/component.txt": []byte("component-b"),
	}
	var sumLines string
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		sumLines += fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), rel)
	}
	if err := os.WriteFile(filepath.Join(dir, "STAGE-SHA256SUMS.txt"), []byte(sumLines), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStageChecksums(dir); err != nil {
		t.Fatalf("valid stage failed checksum check: %v", err)
	}

	// Extra unlisted file must fail.
	extra := filepath.Join(dir, "unlisted.bin")
	if err := os.WriteFile(extra, []byte("extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStageChecksums(dir); err == nil {
		t.Fatal("expected unlisted file to fail VerifyStageChecksums")
	}
	_ = os.Remove(extra)

	// Modified byte must fail.
	if err := os.WriteFile(filepath.Join(dir, "netswitch.exe"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStageChecksums(dir); err == nil {
		t.Fatal("expected tampered file to fail VerifyStageChecksums")
	}

	// Missing file must fail.
	_ = os.Remove(filepath.Join(dir, "netswitch.exe"))
	if err := VerifyStageChecksums(dir); err == nil {
		t.Fatal("expected missing file to fail VerifyStageChecksums")
	}
}

func TestMatchesInstalledDesktopExeAndSelfCommandLine(t *testing.T) {
	root := `C:\Program Files\Net Switch`
	if !matchesInstalledDesktopExe(`C:\Program Files\Net Switch\netswitch-desktop.exe`, root) {
		t.Fatal("expected root launcher to match")
	}
	if !matchesInstalledDesktopExe(`C:\Program Files\Net Switch\app-1.0.0\netswitch-desktop.exe`, root) {
		t.Fatal("expected versioned desktop binary to match")
	}
	if matchesInstalledDesktopExe(`C:\Program Files\Net Switch\other\netswitch-desktop.exe`, root) {
		t.Fatal("non-versioned subdirectory must not match")
	}
	if matchesInstalledDesktopExe(`C:\Elsewhere\netswitch-desktop.exe`, root) {
		t.Fatal("outside directory must not match")
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	exeBase := filepath.Base(os.Args[0])
	if !processCommandLineContains(h, exeBase) {
		t.Fatalf("expected own process command line to contain %q", exeBase)
	}
	if processCommandLineContains(h, "absent-token-9f81c2b0e4") {
		t.Fatal("unexpected match for absent token")
	}
}

func TestParseControlStatusRoutingWantedMatchesAccessStatus(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"on", true},
		{"starting", true},
		{"off", false},
		{"error", false},
	} {
		access := &Access{
			Remote:  &Remote{snapshot: engine.Snapshot{Status: tc.status, Instance: "inst-1"}},
			Desktop: &DesktopBridge{},
		}
		raw, err := json.Marshal(access.status())
		if err != nil {
			t.Fatal(err)
		}
		if got := parseControlStatusRoutingWanted(raw); got != tc.want {
			t.Fatalf("status=%q (%s): got %t, want %t", tc.status, string(raw), got, tc.want)
		}
	}
}
