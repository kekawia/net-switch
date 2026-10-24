package lifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

// The pre-release stand-in build left engine-state.json without the native
// schema and adapter-scope records in the journal. Both the installer and the
// native host refuse such a folder with one clear message; a native folder and
// an empty folder pass. On main nothing checked this.
func TestStandInStoreIsRefused(t *testing.T) {
	empty := t.TempDir()
	if err := refuseStandInStore(empty); err != nil {
		t.Fatal("empty folder refused", err)
	}
	standIn := t.TempDir()
	if err := os.WriteFile(filepath.Join(standIn, "engine-state.json"), []byte(`{"engineInstanceId":"abc","epoch":3,"appliedRevision":null,"exitReason":"adapter-failed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := refuseStandInStore(standIn)
	if err == nil || !strings.Contains(err.Error(), "pre-release stand-in build") || !strings.Contains(err.Error(), "engine-state.json") {
		t.Fatal("stand-in state accepted", err)
	}
	native := t.TempDir()
	if err := os.WriteFile(filepath.Join(native, "engine-state.json"), []byte(`{"schema":1,"engineInstanceId":"abc","epoch":3,"n":2,"hash":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refuseStandInStore(native); err != nil {
		t.Fatal("native folder refused", err)
	}
	scoped := t.TempDir()
	store := &journal.FileStore{Path: filepath.Join(scoped, "engine-journal.json"), SyncParent: SyncDirectory}
	if err := store.Append(journal.Record{ID: "r1", Boot: "b", Instance: "abc", Kind: "adapter-service-scope", Fingerprint: journal.Fingerprint{"service": "NetSwitchEngine"}, Phase: "created"}); err != nil {
		t.Fatal(err)
	}
	err = refuseStandInStore(scoped)
	if err == nil || !strings.Contains(err.Error(), "pre-release stand-in build") || !strings.Contains(err.Error(), "adapter-service-scope") {
		t.Fatal("stand-in journal accepted", err)
	}
	nativeJournal := t.TempDir()
	store = &journal.FileStore{Path: filepath.Join(nativeJournal, "engine-journal.json"), SyncParent: SyncDirectory}
	if err := store.Append(journal.Record{ID: "r2", Boot: "b", Instance: "abc", Kind: "wintun-adapter", Fingerprint: journal.Fingerprint{"guid": "{x}"}, Phase: "created"}); err != nil {
		t.Fatal(err)
	}
	if err := refuseStandInStore(nativeJournal); err != nil {
		t.Fatal("native journal refused", err)
	}
}

// The inspection is read-only. FileStore.Records opens the journal for writing
// and truncates an incomplete tail; the installer and the host call the
// refusal before they own the engine's lifetime lock, so neither may do that.
// A torn tail is skipped for the owner to recover, and the file stays byte for
// byte as it was, whatever the verdict.
func TestStandInInspectionLeavesTheJournalUntouched(t *testing.T) {
	for _, kind := range []string{"wintun-adapter", "adapter-linux-rule"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "engine-journal.json")
		store := &journal.FileStore{Path: path, SyncParent: SyncDirectory}
		if err := store.Append(journal.Record{ID: "r1", Boot: "b", Instance: "abc", Kind: kind, Fingerprint: journal.Fingerprint{"k": "v"}, Phase: "created"}); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"record":{"id":"torn","kind":"adapter-service-scope"`); err != nil {
			t.Fatal(err)
		}
		f.Close()
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		err = refuseStandInStore(dir)
		after, statErr := os.Stat(path)
		if statErr != nil || after.Size() != before.Size() {
			t.Fatal("inspection changed the journal", before.Size(), after, statErr)
		}
		if kind == "wintun-adapter" && err != nil {
			t.Fatal("native journal with a torn tail refused", err)
		}
		if kind == "adapter-linux-rule" && (err == nil || !strings.Contains(err.Error(), kind)) {
			t.Fatal("stand-in journal with a torn tail accepted", err)
		}
	}
}

// The stand-in's service configuration named its sing-box adapter (its CI
// installs also ran proxy mode); the native installer refuses such a folder
// before it would overwrite that file. A folder whose primary state file is
// gone but whose backup is the stand-in's is refused the same way.
func TestStandInConfigurationAndBackupOnlyStateAreRefused(t *testing.T) {
	dir := t.TempDir()
	refused := func(name string) {
		t.Helper()
		err := refuseStandInStore(dir)
		if err == nil || !strings.Contains(err.Error(), "pre-release stand-in build") || !strings.Contains(err.Error(), name) {
			t.Fatal("stand-in state accepted", name, err)
		}
	}
	// Written like the stand-in's installer did (primary and .bak), without
	// the store ACLs the real Save sets, which need an administrator.
	configure := func(c Config) {
		t.Helper()
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"service-config.json", "service-config.json.bak"} {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	configure(Config{Directory: dir, Data: dir, Adapter: filepath.Join(dir, "sing-box.exe"), Mode: "tun"})
	refused("service-config.json")
	configure(Config{Directory: dir, Data: dir, Mode: "proxy"})
	refused("service-config.json")
	configure(Config{Directory: dir, Data: dir, Mode: "tun"})
	if err := refuseStandInStore(dir); err != nil {
		t.Fatal("native configuration refused", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "engine-state.json.bak"), []byte(`{"engineInstanceId":"abc","epoch":3,"appliedRevision":null,"exitReason":"adapter-failed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	refused("engine-state.json.bak")
}
