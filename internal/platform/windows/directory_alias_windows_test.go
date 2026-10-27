package winplatform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	p, _ := windows.UTF16PtrFromString(parent)
	h, err := windows.CreateFile(p, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	// Explicit assignment makes disabled automatic 8.3 generation no excuse
	// for silently losing the regression. Failure is a failed precondition.
	short := fmt.Sprintf("NS%06X", uint64(time.Now().UnixNano())&0xffffff)
	s, _ := windows.UTF16PtrFromString(short)
	ok, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetFileShortNameW").Call(uintptr(h), uintptr(unsafe.Pointer(s)))
	if ok == 0 {
		t.Fatal("explicit short-name assignment failed", e)
	}
	alias := filepath.Join(filepath.Dir(parent), short)
	a, err := os.Stat(alias)
	b, other := os.Stat(parent)
	if err != nil || other != nil || !os.SameFile(a, b) {
		t.Fatal("short alias does not identify the fixture directory", err, other)
	}
	return parent, alias
}

func TestMachineStoreAliases(t *testing.T) {
	parent, short := aliasStoreParent(t)
	for _, spelling := range []struct{ name, parent string }{{"case", strings.ToUpper(parent)}, {"short", short}} {
		t.Run(spelling.name, func(t *testing.T) {
			path := filepath.Join(parent, spelling.name)
			alias := filepath.Join(spelling.parent, spelling.name)
			if err := ProtectDirectory(path); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(path, directoryMarkerName))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyDirectory(alias); err != nil {
				t.Error("alias verification", err)
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
	parent, short := aliasStoreParent(t)
	for _, phase := range []string{"staged", "quarantined"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(parent, phase)
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("interrupted migration")
			err := protectDirectory(path, func(string) {}, func(at string) error {
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
			alias := filepath.Join(short, phase)
			if err := ProtectDirectory(alias); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(path, directoryMarkerName))
			if err != nil || string(before) != string(after) {
				t.Fatal("certified stage was not recovered", err)
			}
			if err := VerifyDirectory(alias); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMachineStoreFallbackAlias(t *testing.T) {
	parent, short := aliasStoreParent(t)
	path := filepath.Join(parent, "fallback")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
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
	for _, alias := range []string{strings.ToUpper(path), filepath.Join(short, "fallback")} {
		resolved, err := ResolveMachineDirectory(alias)
		if err != nil {
			t.Error("alias fallback lookup", err)
			continue
		}
		a, err := os.Stat(fresh)
		b, other := os.Stat(resolved)
		if err != nil || other != nil || !os.SameFile(a, b) {
			t.Error("alias selected a different fallback store", resolved, err, other)
		}
	}
}
