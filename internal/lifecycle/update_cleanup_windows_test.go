package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateCleanupCannotDeleteCurrentOrUnknownVersion(t *testing.T) {
	for _, marker := range []string{"app-1.0.0\n", "not-a-version\n"} {
		t.Run(marker, func(t *testing.T) {
			root := t.TempDir()
			version := filepath.Join(root, "app-1.0.0")
			if err := os.Mkdir(version, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(version, "still-installed.txt")
			if err := os.WriteFile(file, []byte("current"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "current"), []byte(marker), 0600); err != nil {
				t.Fatal(err)
			}
			if err := removeInactiveVersion(root, version); err == nil {
				t.Fatal("removed current or uncertain version")
			}
			if bytes, err := os.ReadFile(file); err != nil || string(bytes) != "current" {
				t.Fatal("validation failure deleted the installed app", err)
			}
		})
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "current"), []byte("app-1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "app-1.1.0")
	if err := os.Mkdir(staged, 0700); err != nil {
		t.Fatal(err)
	}
	if err := removeInactiveVersion(root, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("unused stage was not cleaned", err)
	}
	if err := removeInactiveVersion(root, t.TempDir()); err == nil {
		t.Fatal("cleanup escaped install root")
	}
}
