package wintrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	dirSDDL          = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	execFileSDDL     = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	readOnlyFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"
)

func enableOwnershipPrivileges() {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return
	}
	defer token.Close()
	for _, name := range []string{"SeTakeOwnershipPrivilege", "SeRestorePrivilege"} {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			continue
		}
		privs := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			}},
		}
		_ = windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
	}
}

func hardenSingle(path string, wantDir bool, sddl string) ([]string, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_READ_ATTRIBUTES)
	if wantDir {
		access |= windows.FILE_LIST_DIRECTORY
	}
	h, err := windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		f.Close()
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		f.Close()
		return nil, fmt.Errorf("installation links are refused: %s", path)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDir != wantDir {
		f.Close()
		if wantDir {
			return nil, fmt.Errorf("expected installation directory: %s", path)
		}
		return nil, fmt.Errorf("expected regular installation file: %s", path)
	}
	if !isDir && info.NumberOfLinks != 1 {
		f.Close()
		return nil, fmt.Errorf("installation hard links are refused: %s", path)
	}
	var children []string
	if isDir {
		children, err = f.Readdirnames(-1)
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, acl, nil)
	closeErr := f.Close()
	if err != nil {
		return nil, fmt.Errorf("harden %s: %w", path, err)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := Path(path, false); err != nil {
		return nil, err
	}
	return children, nil
}

// HardenTree sets Administrators ownership and a protected read/execute DACL on
// dir and every descendant without following reparse points or hard links.
func HardenTree(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("installation needs absolute paths: %s", dir)
	}
	enableOwnershipPrivileges()
	return hardenSubtree(filepath.Clean(dir))
}

func hardenSubtree(dir string) error {
	children, err := hardenSingle(dir, true, dirSDDL)
	if err != nil {
		return err
	}
	for _, name := range children {
		child := filepath.Join(dir, name)
		p, err := windows.UTF16PtrFromString(child)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return err
		}
		var info windows.ByHandleFileInformation
		infoErr := windows.GetFileInformationByHandle(h, &info)
		_ = windows.CloseHandle(h)
		if infoErr != nil {
			return infoErr
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("installation links are refused: %s", child)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			if err := hardenSubtree(child); err != nil {
				return err
			}
			continue
		}
		if _, err := hardenSingle(child, false, execFileSDDL); err != nil {
			return err
		}
	}
	return nil
}

func checkAncestorsAbove(dir string) error {
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		if err := Path(parent, true); err != nil {
			return err
		}
		if filepath.Dir(parent) == parent {
			return nil
		}
	}
}

// HardenInstallation verifies every ancestor above appDir, hardens appDir
// itself without modifying sibling 0.3.x files before commit, and hardens the
// staged versionDir subtree.
func HardenInstallation(appDir, versionDir string) error {
	if !filepath.IsAbs(appDir) || !filepath.IsAbs(versionDir) {
		return fmt.Errorf("installation needs absolute paths")
	}
	appDir = filepath.Clean(appDir)
	versionDir = filepath.Clean(versionDir)
	if !strings.EqualFold(filepath.Dir(versionDir), appDir) {
		return fmt.Errorf("version directory %s must sit directly under %s", versionDir, appDir)
	}
	enableOwnershipPrivileges()
	if err := checkAncestorsAbove(appDir); err != nil {
		return err
	}
	if _, err := hardenSingle(appDir, true, dirSDDL); err != nil {
		return err
	}
	if err := Path(appDir, true); err != nil {
		return err
	}
	return hardenSubtree(versionDir)
}

// HardenRootFiles hardens the stable top-level launcher, current version
// marker, and shortcut icon in appDir after commit or install.
func HardenRootFiles(appDir string) error {
	if !filepath.IsAbs(appDir) {
		return fmt.Errorf("installation needs absolute paths")
	}
	appDir = filepath.Clean(appDir)
	enableOwnershipPrivileges()
	if err := checkAncestorsAbove(appDir); err != nil {
		return err
	}
	if _, err := hardenSingle(appDir, true, dirSDDL); err != nil {
		return err
	}
	if _, err := hardenSingle(filepath.Join(appDir, "current"), false, readOnlyFileSDDL); err != nil {
		return err
	}
	if _, err := hardenSingle(filepath.Join(appDir, "netswitch-desktop.exe"), false, execFileSDDL); err != nil {
		return err
	}
	assetsDir := filepath.Join(appDir, "assets")
	if _, err := hardenSingle(assetsDir, true, dirSDDL); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	iconPath := filepath.Join(assetsDir, "net-switch.ico")
	if _, err := hardenSingle(iconPath, false, readOnlyFileSDDL); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
