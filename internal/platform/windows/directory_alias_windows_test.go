package winplatform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var shortAliasSeq atomic.Uint32

func assignShortName(t *testing.T, target string) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	// Explicit assignment makes disabled automatic 8.3 generation no excuse
	// for silently losing the regression. Failure is a failed precondition.
	seq := shortAliasSeq.Add(1)
	short := fmt.Sprintf("NS%04X%02X", uint64(time.Now().UnixNano())&0xffff, seq&0xff)
	s, err := windows.UTF16PtrFromString(short)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetFileShortNameW").Call(uintptr(h), uintptr(unsafe.Pointer(s)))
	if ok == 0 {
		t.Fatal("explicit short-name assignment failed", e)
	}
	alias := filepath.Join(filepath.Dir(target), short)
	a, err := os.Stat(alias)
	b, other := os.Stat(target)
	if err != nil || other != nil || !os.SameFile(a, b) {
		t.Fatal("short alias does not identify the fixture directory", err, other)
	}
	return short
}

func aliasStoreParent(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("privileged alias regression runs on hosted Windows only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("alias regression requires elevation")
	}
	parent := filepath.Join(os.Getenv("ProgramData"), fmt.Sprintf("NetSwitch-alias-%d", time.Now().UnixNano()))
	if err := ProtectDirectory(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	short := assignShortName(t, parent)
	return parent, filepath.Join(filepath.Dir(parent), short)
}

func TestCanonicalMachinePathAliases(t *testing.T) {
	base, err := canonicalMachinePath(filepath.Join(t.TempDir(), "probe"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(base)
	parent := filepath.Join(root, "NetSwitch-Parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	shortParentName := assignShortName(t, parent)
	shortParent := filepath.Join(root, shortParentName)

	store := filepath.Join(parent, "NetSwitch-Store")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	shortStoreName := assignShortName(t, store)

	wantCert := directoryCertificateName(store)
	for _, alias := range []string{
		store,
		strings.ToUpper(store),
		strings.ToLower(store),
		filepath.Join(shortParent, "NetSwitch-Store"),
		filepath.Join(parent, shortStoreName),
		filepath.Join(shortParent, shortStoreName),
		filepath.Join(strings.ToLower(shortParent), strings.ToLower(shortStoreName)),
	} {
		got, err := canonicalMachinePath(alias)
		if err != nil {
			t.Fatalf("canonicalMachinePath(%q): %v", alias, err)
		}
		if got != store {
			t.Fatalf("canonicalMachinePath(%q) = %q, want %q", alias, got, store)
		}
		if cert := directoryCertificateName(alias); cert != wantCert {
			t.Fatalf("directoryCertificateName(%q) = %q, want %q", alias, cert, wantCert)
		}
	}

	// Simulate the "quarantined" crash window where the target directory was
	// moved aside to <target>.untrusted-<24-hex> and <target>.migrating exists.
	pending := filepath.Join(parent, "NetSwitch-Pending")
	if err := os.Mkdir(pending, 0700); err != nil {
		t.Fatal(err)
	}
	shortPendingName := assignShortName(t, pending)
	pPending, err := windows.UTF16PtrFromString(pending)
	if err != nil {
		t.Fatal(err)
	}
	hPending, err := windows.CreateFile(pPending, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameDirectoryHandle(hPending, pending+".untrusted-"+strings.Repeat("a", 24)); err != nil {
		windows.CloseHandle(hPending)
		t.Fatal(err)
	}
	windows.CloseHandle(hPending)
	if err := os.Mkdir(pending+".migrating", 0700); err != nil {
		t.Fatal(err)
	}
	if found, ok, err := findLongEntryName(parent, shortPendingName); err != nil || ok {
		t.Fatalf("quarantine rename retained old short alias %q -> %q (%v)", shortPendingName, found, err)
	}
	for _, alias := range []string{
		filepath.Join(shortParent, "NetSwitch-Pending"),
		filepath.Join(shortParent, "NETSWITCH-PENDING"),
		filepath.Join(parent, "netswitch-pending"),
	} {
		got, err := canonicalMachinePath(alias)
		if err != nil {
			t.Fatalf("pending canonicalMachinePath(%q): %v", alias, err)
		}
		if got != pending {
			t.Fatalf("pending canonicalMachinePath(%q) = %q, want %q", alias, got, pending)
		}
	}

	// Wildcards in the leaf must be rejected rather than matching entries via FindFirstFile.
	for _, bad := range []string{
		filepath.Join(parent, "NetSwitch-*"),
		filepath.Join(parent, "NetSwitch-?tore"),
	} {
		if got, err := canonicalMachinePath(bad); err == nil {
			t.Fatalf("wildcard path %q resolved to %q", bad, got)
		}
	}

	// Reparse ancestors must be refused before canonicalization.
	junction := filepath.Join(root, "junction-parent")
	plantMachineOccupant(t, junction, "junction", parent)
	if got, err := canonicalMachinePath(filepath.Join(junction, "NetSwitch-Store")); err == nil {
		t.Fatalf("reparse ancestor resolved to %q", got)
	}
}

func TestMachineStoreAliases(t *testing.T) {
	parent, shortParent := aliasStoreParent(t)
	for _, tc := range []struct {
		name      string
		makeAlias func(path, shortLeaf string) string
	}{
		{"case", func(path, _ string) string { return strings.ToUpper(path) }},
		{"short-parent", func(path, _ string) string { return filepath.Join(shortParent, filepath.Base(path)) }},
		{"short-leaf", func(_, shortLeaf string) string { return filepath.Join(parent, shortLeaf) }},
		{"short-both", func(_, shortLeaf string) string { return filepath.Join(shortParent, shortLeaf) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(parent, "store-"+tc.name)
			if err := ProtectDirectory(path); err != nil {
				t.Fatal(err)
			}
			shortLeaf := assignShortName(t, path)
			alias := tc.makeAlias(path, shortLeaf)
			before, err := os.ReadFile(filepath.Join(path, directoryMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyDirectory(alias); err != nil {
				t.Fatal("alias verification", err)
			}
			resolved, err := PrepareMachineDirectory(alias)
			if err != nil {
				t.Fatal("alias preparation", err)
			}
			after, err := os.ReadFile(filepath.Join(resolved, directoryMarkerName))
			if err != nil || string(before) != string(after) {
				t.Fatal("alias preparation replaced the certified store", err)
			}
			resolved, err = ResolveMachineDirectory(alias)
			if err != nil {
				t.Fatal(err)
			}
			a, err := os.Stat(path)
			b, other := os.Stat(resolved)
			if err != nil || other != nil || !os.SameFile(a, b) {
				t.Fatal("alias location differs", err, other)
			}
		})
	}
}

func TestMachineStoreStagedAlias(t *testing.T) {
	parent, shortParent := aliasStoreParent(t)
	for _, phase := range []string{"staged", "quarantined"} {
		for _, kind := range []string{"short-parent", "case", "short-leaf"} {
			if phase == "quarantined" && kind == "short-leaf" {
				// After quarantine moves the original leaf aside, the leaf
				// directory entry does not exist until stage publication.
				continue
			}
			t.Run(phase+"/"+kind, func(t *testing.T) {
				leaf := fmt.Sprintf("stage-%s-%s", phase, kind)
				path := filepath.Join(parent, leaf)
				trustedLegacyDirectory(t, path)
				if err := os.WriteFile(filepath.Join(path, "windows-undo.json"), []byte(validUndo), 0600); err != nil {
					t.Fatal(err)
				}
				shortLeaf := assignShortName(t, path)
				original, err := eagerFileInfo(path)
				if err != nil {
					t.Fatal(err)
				}
				interrupted := errors.New("interrupted migration")
				err = protectDirectory(path, func(string) {}, func(at string) error {
					if at == phase {
						return interrupted
					}
					return nil
				})
				if !errors.Is(err, interrupted) {
					t.Fatal("did not reach checkpoint", err)
				}
				before, err := os.ReadFile(filepath.Join(path+".migrating", directoryMarkerName))
				if err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(shortParent, leaf)
				switch kind {
				case "case":
					alias = strings.ToUpper(path)
				case "short-leaf":
					alias = filepath.Join(parent, shortLeaf)
				}
				if err := ProtectDirectory(alias); err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(filepath.Join(path, directoryMarkerName))
				if err != nil || string(before) != string(after) {
					t.Fatal("certified stage was not recovered", err)
				}
				if undo, err := os.ReadFile(filepath.Join(path, "windows-undo.json")); err != nil || string(undo) != validUndo {
					t.Fatal("staged alias recovery lost Undo", string(undo), err)
				}
				old, err := filepath.Glob(path + ".untrusted-*")
				if err != nil || len(old) != 1 {
					t.Fatal("original tree was not quarantined once", old, err)
				}
				quarantined, err := eagerFileInfo(old[0])
				if err != nil || !os.SameFile(original, quarantined) {
					t.Fatal("quarantine lost original directory identity", err)
				}
				if kind == "short-leaf" {
					// Publishing the staged directory replaces the directory object
					// at path, so the old object's explicit 8.3 short name does not
					// belong to the new object. Assign a short name to the recovered
					// directory before verifying through a short-leaf alias.
					alias = filepath.Join(parent, assignShortName(t, path))
				}
				if err := VerifyDirectory(alias); err != nil {
					t.Fatal(err)
				}
				if err := VerifyDirectory(path); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestMachineStoreFallbackAlias(t *testing.T) {
	parent, shortParent := aliasStoreParent(t)
	path := filepath.Join(parent, "fallback")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	shortLeaf := assignShortName(t, path)
	p, _ := windows.UTF16PtrFromString(filepath.Join(path, "held"))
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	fresh, err := PrepareMachineDirectory(path)
	if err != nil || fresh == path {
		t.Fatal("fixture did not publish a fallback store", fresh, err)
	}
	a, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{
		strings.ToUpper(path),
		filepath.Join(shortParent, "fallback"),
		filepath.Join(parent, shortLeaf),
		filepath.Join(shortParent, shortLeaf),
	} {
		resolved, err := ResolveMachineDirectory(alias)
		if err != nil {
			t.Fatal("alias fallback lookup", alias, err)
		}
		b, other := os.Stat(resolved)
		if other != nil || !os.SameFile(a, b) {
			t.Fatal("alias selected a different fallback store", alias, resolved, other)
		}
		prepared, err := PrepareMachineDirectory(alias)
		if err != nil {
			t.Fatal("alias fallback prepare", alias, err)
		}
		c, other := os.Stat(prepared)
		if other != nil || !os.SameFile(a, c) {
			t.Fatal("alias prepare replaced fallback store", alias, prepared, other)
		}
	}
}

func TestMachineStoreCleanupAlias(t *testing.T) {
	parent, shortParent := aliasStoreParent(t)
	path := filepath.Join(parent, "cleanup-store")
	if err := ProtectDirectory(path); err != nil {
		t.Fatal(err)
	}
	shortLeaf := assignShortName(t, path)
	old := path + ".untrusted-" + strings.Repeat("a", 24)
	stage := path + ".migrating"
	for _, extra := range []string{old, stage} {
		if err := ProtectDirectory(extra); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(shortParent, shortLeaf)
	if err := PrepareMachineUninstall(alias, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err := CleanupMachineData(alias, func(string) {}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{path, old, stage} {
		if _, err := os.Lstat(item); !os.IsNotExist(err) {
			t.Fatal("cleanup via alias left machine artifact behind", item, err)
		}
	}
	if cert, err := directoryCertificate(path); err != nil || cert != "" {
		t.Fatal("cleanup via alias left machine certificate behind", cert, err)
	}
}
