package sharedfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenKeepsNotExist(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.log")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing file must stay a not-exist error:", err)
	}
}

// Control rotates its log by renaming it while a report may be reading it;
// the reader's handle must not refuse that rename (FILE_SHARE_DELETE).
func TestOpenReaderDoesNotBlockRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NetSwitch.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal("rotation refused while the log was open for reading:", err)
	}
}
