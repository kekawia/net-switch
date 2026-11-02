package winplatform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
)

func validateMachineLeaf(path, base string) error {
	if filepath.Dir(path) == path || base == "" || base == "." || base == ".." || strings.ContainsAny(base, `*?\/:`) {
		return fmt.Errorf("invalid machine-store path: %s", path)
	}
	return nil
}

// pinMachineParent opens and pins every ancestor of path from the volume root
// down to filepath.Dir(path) without following reparse points, optionally
// checking installation-grade ancestor ACLs, and returns the canonical long
// path for path along with a release function for the held ancestor handles.
func pinMachineParent(path string, checkTrust bool) (string, func(), error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	base := filepath.Base(path)
	if err := validateMachineLeaf(path, base); err != nil {
		return "", nil, err
	}
	var ancestors []string
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		ancestors = append(ancestors, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	var held []windows.Handle
	release := func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = windows.CloseHandle(held[i])
		}
		held = nil
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		parent := ancestors[i]
		if checkTrust {
			if err := wintrust.Path(parent, true); err != nil {
				release()
				return "", nil, err
			}
		}
		p, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			release()
			return "", nil, err
		}
		// Metadata-only handles do not enforce delete sharing. Directory
		// read access makes this handle pin the ancestor against renames.
		h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			release()
			return "", nil, err
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			release()
			return "", nil, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			release()
			return "", nil, fmt.Errorf("machine-store ancestor is a reparse point")
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			release()
			return "", nil, fmt.Errorf("machine-store ancestor is not a directory: %s", parent)
		}
	}
	canonical, err := canonicalizeFromPinnedParent(held[len(held)-1], base)
	if err != nil {
		release()
		return "", nil, err
	}
	return canonical, release, nil
}

func canonicalMachinePath(path string) (string, error) {
	canonical, release, err := pinMachineParent(path, false)
	if err != nil {
		return "", err
	}
	release()
	return canonical, nil
}

func canonicalizeFromPinnedParent(parentHandle windows.Handle, base string) (string, error) {
	if base == "" || base == "." || base == ".." || strings.ContainsAny(base, `*?\/:`) {
		return "", fmt.Errorf("invalid machine-store leaf %q", base)
	}
	parentDir, err := finalPathByHandle(parentHandle)
	if err != nil {
		return "", err
	}
	leaf, err := canonicalLeafName(parentDir, base)
	if err != nil {
		return "", err
	}
	return filepath.Join(parentDir, leaf), nil
}

//go:noinline
func newPathBuffer() *[32768]uint16 {
	return new([32768]uint16)
}

//go:noinline
func newFindData() *windows.Win32finddata {
	return new(windows.Win32finddata)
}

func finalPathByHandle(h windows.Handle) (string, error) {
	// Heap-allocated buffer for GetFinalPathNameByHandleW.
	buf := newPathBuffer()
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || int(n) >= len(buf) {
		return "", fmt.Errorf("canonical parent path length %d out of bounds", n)
	}
	raw := windows.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(raw, `\\?\UNC\`):
		raw = `\\` + strings.TrimPrefix(raw, `\\?\UNC\`)
	case strings.HasPrefix(raw, `\\?\`):
		raw = strings.TrimPrefix(raw, `\\?\`)
	}
	return filepath.Clean(raw), nil
}

func canonicalLeafName(parentDir, base string) (string, error) {
	if found, ok, err := findLongEntryName(parentDir, base); err != nil {
		return "", err
	} else if ok {
		return found, nil
	}
	const migratingSuffix = ".migrating"
	if found, ok, err := findLongEntryName(parentDir, base+migratingSuffix); err != nil {
		return "", err
	} else if ok && len(found) > len(migratingSuffix) && strings.EqualFold(found[len(found)-len(migratingSuffix):], migratingSuffix) {
		return found[:len(found)-len(migratingSuffix)], nil
	}
	return base, nil
}

func findLongEntryName(parentDir, name string) (string, bool, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `*?\/:`) {
		return "", false, fmt.Errorf("invalid machine-store entry %q", name)
	}
	pattern, err := windows.UTF16PtrFromString(filepath.Join(parentDir, name))
	if err != nil {
		return "", false, err
	}
	fd := newFindData()
	h, err := windows.FindFirstFile(pattern, fd)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	_ = windows.FindClose(h)
	found := windows.UTF16ToString(fd.FileName[:])
	if found == "" || found == "." || found == ".." {
		return "", false, nil
	}
	return found, true, nil
}
