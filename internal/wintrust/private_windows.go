package wintrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const privateFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

func privateAttributes(sddl string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func privateHandle(h windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		return errors.New("update storage must contain only plain directories and single-link files")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	admin := func(sid *windows.SID) bool {
		return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !admin(owner) {
		return errors.New("update storage must be owned by SYSTEM or Administrators")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("update storage has no private access list")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (ace.Mask != 0 && !admin((*windows.SID)(unsafe.Pointer(&ace.SidStart)))) {
			return errors.New("update storage grants access outside SYSTEM and Administrators")
		}
	}
	return nil
}

// EnsurePrivateDirectory sets security at creation. An existing writable folder
// is refused, never made trusted by tightening an ACL after handles were opened.
func EnsurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("update storage needs an absolute path")
	}
	if err := checkAncestorsAbove(path); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa, err := privateAttributes(privateDirSDDL)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return privateHandle(h, true)
}

// PinPrivateDirectory prevents replacement while its caller uses child paths.
func PinPrivateDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("update storage needs an absolute path")
	}
	if err := checkAncestorsAbove(path); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err := privateHandle(h, true); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func OpenPrivateFile(path string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("update file needs an absolute path")
	}
	parent, err := PinPrivateDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access, disposition := uint32(windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES), uint32(windows.OPEN_EXISTING)
	var sa *windows.SecurityAttributes
	if create {
		access |= windows.GENERIC_WRITE
		disposition = windows.CREATE_NEW
		sa, err = privateAttributes(privateFileSDDL)
		if err != nil {
			return nil, err
		}
	}
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ, sa, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err := privateHandle(h, false); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("private update file: %w", err)
	}
	return os.NewFile(uintptr(h), path), nil
}
