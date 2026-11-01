package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

func TestRetiredJournalIsCompacted(t *testing.T) {
	dir := t.TempDir()
	store := &journal.FileStore{Path: filepath.Join(dir, "journal"), SyncParent: func(string) error { return nil }}
	record := journal.Record{ID: "old", Phase: "created"}
	if err := store.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearRetired(); err == nil {
		t.Fatal("compacted a live record")
	}
	record.Phase = "removed"
	if err := store.Append(record); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(store.Path)
	if err != nil || before.Size() == 0 {
		t.Fatal("missing journal precondition", err)
	}
	if err := store.ClearRetired(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(store.Path)
	if err != nil || after.Size() != 0 {
		t.Fatal("retired journal grew across starts", err)
	}
}
