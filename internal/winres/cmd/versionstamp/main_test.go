package main

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func programRoot(t *testing.T, skip string) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range programs {
		if p.dir == skip {
			continue
		}
		if err := os.MkdirAll(filepath.Join(root, "cmd", p.dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestStampWritesEveryProgramsObjectAndSaysWhere(t *testing.T) {
	root := programRoot(t, "")
	written, err := stamp(root, "arm64", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != len(programs) {
		t.Fatalf("wrote %v; want one file per program", written)
	}
	for i, p := range programs {
		want := filepath.Join(root, "cmd", p.dir, "zz_version_windows_arm64.syso")
		if written[i] != want {
			t.Errorf("wrote %s; want %s", written[i], want)
		}
		object, err := os.ReadFile(want)
		if err != nil {
			t.Fatal(err)
		}
		f, err := pe.NewFile(bytes.NewReader(object))
		if err != nil || f.Machine != 0xAA64 {
			t.Fatalf("%s: %v, machine %#x", p.dir, err, f.Machine)
		}
		for _, text := range []string{p.description, p.dir + ".exe", "Net Switch", "1.0.0"} {
			if !bytes.Contains(object, utf16Bytes(text)) {
				t.Errorf("%s doesn't say %q", p.dir, text)
			}
		}
	}
}

// What a running program is called in Task Manager. Net Switch's own app
// list names programs by this too and drops names over 60 characters.
func TestEachDescriptionNamesNetSwitchInPlainWords(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range programs {
		if !strings.HasPrefix(p.description, productName) || len([]rune(p.description)) > 60 || seen[p.description] {
			t.Errorf("%s: %q must start with %q, fit 60 characters and differ from the others", p.dir, p.description, productName)
		}
		seen[p.description] = true
	}
}

func TestStampStopsAtAMissingProgramAndReportsWhatItWrote(t *testing.T) {
	root := programRoot(t, "netswitch-worker")
	written, err := stamp(root, "amd64", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "netswitch-worker") {
		t.Fatalf("error %v; want one naming the missing folder", err)
	}
	if len(written) != 2 {
		t.Fatalf("reported %v; want the two written before the gap", written)
	}
	for _, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("reported %s but it isn't there: %v", path, err)
		}
	}
}

func TestStampRefusesBadInputBeforeWritingAnything(t *testing.T) {
	for _, c := range []struct{ arch, version string }{{"amd64", "1.0.0-dev"}, {"amd64", "70000.0.0"}, {"386", "1.0.0"}, {"", "1.0.0"}} {
		root := programRoot(t, "")
		written, err := stamp(root, c.arch, c.version)
		if err == nil || len(written) != 0 {
			t.Errorf("%s %s: wrote %v, error %v", c.arch, c.version, written, err)
		}
	}
}

func utf16Bytes(s string) []byte {
	var b []byte
	for _, unit := range utf16.Encode([]rune(s)) {
		b = append(b, byte(unit), byte(unit>>8))
	}
	return b
}
