package journal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileTailRecoveryAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine-journal.json")
	syncs := 0
	store := &FileStore{Path: path, SyncParent: func(string) error { syncs++; return nil }}
	r := Record{ID: "1", Boot: "boot", Instance: "engine", Kind: "route", Phase: "intent", Fingerprint: fingerprint()}
	if err := store.Append(r); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatal("parent durability missing")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte(`{"torn`))
	file.Close()
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("torn tail recovery", err)
	}
	r.Phase = "created"
	if err := store.Append(r); err != nil {
		t.Fatal(err)
	}
	records, err = store.Records()
	if err != nil || len(records) != 2 {
		t.Fatal(err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("{\"record\":{},\"sha256\":\"wrong\"}\n"))
	file.Close()
	if records, err := store.Records(); err != nil || len(records) != 2 {
		t.Fatal("garbled final line was not recovered", err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("garbled\nanother line\n"))
	file.Close()
	if _, err := store.Records(); err == nil {
		t.Fatal("interior corruption silently ignored")
	}
}

// ReadOnly shares the owner's frame decoder (bounded lines, checksums, one
// record or one batch per frame) but never truncates: a torn tail stays for
// the owner, and the file is unchanged byte for byte.
func TestReadOnlyDecodesLikeTheOwnerWithoutTouchingTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine-journal.json")
	if _, err := ReadOnly(path); err != nil {
		t.Fatal("missing journal is not empty", err)
	}
	store := &FileStore{Path: path, SyncParent: func(string) error { return nil }}
	r := Record{ID: "1", Boot: "boot", Instance: "engine", Kind: "route", Phase: "intent", Fingerprint: fingerprint()}
	if err := store.Append(r); err != nil {
		t.Fatal(err)
	}
	r.ID = "2"
	if err := store.AppendBatch([]Record{r, r}); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte(`{"record":{"id":"torn"`))
	file.Close()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadOnly(path)
	if err != nil || len(records) != 3 || records[0].ID != "1" || records[2].ID != "2" {
		t.Fatal("read-only listing", records, err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Size() != before.Size() {
		t.Fatal("read-only inspection changed the journal", before.Size(), after, err)
	}
	owned, err := store.Records()
	if err != nil || len(owned) != 3 {
		t.Fatal("owner recovery after inspection", owned, err)
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("{\"record\":{},\"sha256\":\"wrong\"}\nanother line\n"))
	file.Close()
	if _, err := ReadOnly(path); err == nil {
		t.Fatal("read-only inspection accepted interior corruption")
	}
}
