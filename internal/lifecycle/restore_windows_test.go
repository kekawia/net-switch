package lifecycle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

func testUndoFiles() settings.Files {
	if Administrator() {
		return durableFiles{}
	}
	return nil
}

func TestRestoreWindowsWithEmptyAndMissingRecords(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	err := restoreWindowsWith(dir, testUndoFiles(), &out, &errOut,
		func(any) error { t.Fatal("policySet must not run"); return nil },
		func(string, []any) error { t.Fatal("metricsRestore must not run"); return nil },
	)
	if err != nil {
		t.Fatalf("missing record returned error: %v", err)
	}
	if strings.TrimSpace(out.String()) != "Nothing to undo." {
		t.Fatalf("unexpected stdout %q", out.String())
	}

	// Missing primary while backup exists must fail closed without altering backup.
	bakPath := filepath.Join(dir, "windows-undo.json.bak")
	bakBytes := []byte(`{"metrics":{},"policy":{"value":1}}`)
	if err := os.WriteFile(bakPath, bakBytes, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if err := restoreWindowsWith(dir, testUndoFiles(), &out, &errOut,
		func(any) error { t.Fatal("policySet must not run"); return nil },
		func(string, []any) error { t.Fatal("metricsRestore must not run"); return nil },
	); err == nil {
		t.Fatal("expected error when primary missing and backup exists")
	}
	gotBak, err := os.ReadFile(bakPath)
	if err != nil || !bytes.Equal(gotBak, bakBytes) {
		t.Fatalf("backup mutated: %v %q", err, gotBak)
	}
}

func TestRestoreWindowsWithDamagedRecordKeepsDiskUntouched(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"corrupt-json", `{"metrics":`},
		{"non-object", `["bad"]`},
		{"bad-policy-type", `{"metrics":{},"policy":"wrong"}`},
		{"bad-policy-float", `{"metrics":{},"policy":{"value":1.5}}`},
		{"bad-metric-entry", `{"metrics":{"Ethernet":[{"family":"IPv4","automatic":"no","metric":10}]},"policy":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			undoPath := filepath.Join(dir, "windows-undo.json")
			if err := os.WriteFile(undoPath, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			err := restoreWindowsWith(dir, testUndoFiles(), &out, &errOut,
				func(any) error { t.Fatal("policySet must not run"); return nil },
				func(string, []any) error { t.Fatal("metricsRestore must not run"); return nil },
			)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 1 || entries[0].Name() != "windows-undo.json" {
				t.Fatalf("damaged record must not create extra files, got %v", entries)
			}
			after, readErr := os.ReadFile(undoPath)
			if readErr != nil || string(after) != tc.raw {
				t.Fatalf("damaged record modified: %q != %q", after, tc.raw)
			}
		})
	}
}

func TestRestoreWindowsWithFullAndPartialAdapterRecovery(t *testing.T) {
	dir := t.TempDir()
	undoPath := filepath.Join(dir, "windows-undo.json")
	initial := `{"metrics":{"Wi-Fi":[{"family":"IPv4","automatic":true,"metric":25}],"2":[{"family":"IPv4","automatic":false,"metric":10}],"USB":[{"family":"IPv6","automatic":true,"metric":50}]},"policy":{"value":null}}`
	if err := writeStoreFileIfElevatedOrStandard(undoPath, []byte(initial)); err != nil {
		t.Fatal(err)
	}

	var policyCalls []any
	var metricOrder []string
	var out, errOut bytes.Buffer
	err := restoreWindowsWith(dir, testUndoFiles(), &out, &errOut,
		func(v any) error {
			policyCalls = append(policyCalls, v)
			return nil
		},
		func(alias string, rows []any) error {
			metricOrder = append(metricOrder, alias)
			if alias == "Wi-Fi" {
				return errors.New("adapter unplugged")
			}
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected partial error when Wi-Fi is unreachable")
	}
	if !reflect.DeepEqual(policyCalls, []any{nil}) {
		t.Fatalf("expected nil policy restore call, got %#v", policyCalls)
	}
	// JS integer key "2" comes before string keys "Wi-Fi" and "USB".
	if !reflect.DeepEqual(metricOrder, []string{"2", "Wi-Fi", "USB"}) {
		t.Fatalf("unexpected alias order %v", metricOrder)
	}
	if !strings.Contains(out.String(), "Undone, except the settings of Wi-Fi") {
		t.Fatalf("unexpected partial message: %q", out.String())
	}

	// Second run after reconnecting Wi-Fi should finish only Wi-Fi and succeed.
	policyCalls = nil
	metricOrder = nil
	out.Reset()
	errOut.Reset()
	err = restoreWindowsWith(dir, testUndoFiles(), &out, &errOut,
		func(v any) error {
			policyCalls = append(policyCalls, v)
			return nil
		},
		func(alias string, rows []any) error {
			metricOrder = append(metricOrder, alias)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("second run failed: %v (%s)", err, errOut.String())
	}
	if len(policyCalls) != 0 {
		t.Fatalf("policy should already have been cleared, got %v", policyCalls)
	}
	if !reflect.DeepEqual(metricOrder, []string{"Wi-Fi"}) {
		t.Fatalf("expected only Wi-Fi remaining, got %v", metricOrder)
	}
	if strings.TrimSpace(out.String()) != "Windows settings are back as they were before Net Switch changed them." {
		t.Fatalf("unexpected success message: %q", out.String())
	}
}

func writeStoreFileIfElevatedOrStandard(path string, data []byte) error {
	if Administrator() {
		return writeStoreFile(path, data, 0600)
	}
	return os.WriteFile(path, data, 0600)
}
