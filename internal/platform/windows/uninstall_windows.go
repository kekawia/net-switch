package winplatform

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ReadDirectoryQuarantine reads the verified quarantine path recorded in path's
// certified directory marker, returning "" when no quarantine was created.
func ReadDirectoryQuarantine(path string) (string, error) {
	canonical, release, err := pinMachineParent(path, true)
	if err != nil {
		return "", err
	}
	defer release()
	certificate, err := directoryCertificate(canonical)
	if err != nil {
		return "", err
	}
	if certificate == "" {
		return "", fmt.Errorf("machine store has no installation certificate")
	}
	openNoFollow := func(name string) (*os.File, windows.ByHandleFileInformation, error) {
		var info windows.ByHandleFileInformation
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, info, err
		}
		h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, info, err
		}
		f := os.NewFile(uintptr(h), name)
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			f.Close()
			return nil, info, err
		}
		return f, info, nil
	}
	rootFile, rootInfo, err := openNoFollow(canonical)
	if err != nil {
		return "", err
	}
	defer rootFile.Close()
	if rootInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || rootInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", fmt.Errorf("machine store is not a plain directory")
	}
	rootIdentity := fmt.Sprintf("%08x:%08x%08x", rootInfo.VolumeSerialNumber, rootInfo.FileIndexHigh, rootInfo.FileIndexLow)
	markerFile, markerInfo, err := openNoFollow(filepath.Join(canonical, directoryMarkerName))
	if err != nil {
		return "", err
	}
	defer markerFile.Close()
	if markerInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || markerInfo.NumberOfLinks != 1 {
		return "", fmt.Errorf("machine-store marker is not a plain single-link file")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(markerFile.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(markerFile, 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return "", fmt.Errorf("read machine-store marker: %w", err)
	}
	m, ok := parseDirectoryMarker(sd, data, rootIdentity, canonical, certificate)
	if !ok {
		return "", fmt.Errorf("machine-store marker failed verification")
	}
	return m.Quarantine, nil
}

// RollbackPreparedDirectory removes an uncommitted 1.0 machine store without
// touching quarantined legacy trees, removes its HKLM certificate, and renames
// quarantinePath back to originalPath when present.
func RollbackPreparedDirectory(originalPath, storePath, quarantinePath string, log func(string)) error {
	if log == nil {
		log = func(string) {}
	}
	canonicalOriginal, releaseOrig, err := pinMachineParent(originalPath, false)
	if err != nil {
		return err
	}
	defer releaseOrig()
	if storePath == "" {
		storePath = canonicalOriginal
	}
	canonicalStore, err := canonicalMachinePath(storePath)
	if err != nil {
		return err
	}
	removeAdminTree := func(target string) error {
		f, err := openNoFollowDeleteTree(target)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		f.Close()
		return removeExactAdminDirectory(target, log)
	}
	for _, candidate := range []string{canonicalStore, canonicalStore + ".migrating"} {
		if err := removeAdminTree(candidate); err != nil {
			return err
		}
	}
	if key, kErr := openDirectoryCertificates(true); kErr == nil {
		_ = key.DeleteValue(directoryCertificateName(canonicalStore))
		if !strings.EqualFold(canonicalStore, canonicalOriginal) {
			_ = key.DeleteValue("store-" + directoryCertificateName(canonicalOriginal))
		} else {
			_ = key.DeleteValue(directoryCertificateName(canonicalOriginal))
		}
		info, statErr := key.Stat()
		key.Close()
		if statErr == nil && info.ValueCount == 0 && info.SubKeyCount == 0 {
			if software, sErr := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE|registry.WOW64_64KEY); sErr == nil {
				_ = registry.DeleteKey(software, strings.TrimPrefix(directoryCertificateKey, `SOFTWARE\`))
				software.Close()
			}
		}
	} else if !errors.Is(kErr, registry.ErrNotExist) {
		return kErr
	}
	if !strings.EqualFold(canonicalStore, canonicalOriginal) || quarantinePath == "" {
		return nil
	}
	canonicalQuarantine, err := canonicalMachinePath(quarantinePath)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(canonicalQuarantine)
	if err != nil {
		return err
	}
	var ntName windows.NTUnicodeString
	if err := windows.RtlDosPathNameToNtPathName(p, &ntName, nil, nil); err != nil {
		return err
	}
	defer func() {
		windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlFreeUnicodeString").Call(uintptr(unsafe.Pointer(&ntName)))
	}()
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: &ntName, Attributes: windows.OBJ_CASE_INSENSITIVE}
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&h, windows.DELETE, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT, 0, 0); err != nil {
		return fmt.Errorf("open quarantined legacy folder %s: %w", canonicalQuarantine, err)
	}
	defer windows.CloseHandle(h)
	if err := renameDirectoryHandle(h, canonicalOriginal); err != nil {
		return err
	}
	log("restored quarantined machine folder from " + canonicalQuarantine + " to " + canonicalOriginal)
	return nil
}

func openNoFollowDeleteTree(name string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.DELETE|windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), name), nil
}

func removeExactAdminDirectory(target string, log func(string)) error {
	var remove func(string) error
	remove = func(name string) error {
		f, err := openNoFollowDeleteTree(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		h := windows.Handle(f.Fd())
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		if owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
			return fmt.Errorf("refusing to remove non-admin-owned entry %s", name)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
			if !trustedMachineSecurity(sd) {
				return fmt.Errorf("refusing to remove directory with untrusted permissions %s", name)
			}
			children, err := f.Readdirnames(-1)
			if err != nil {
				return err
			}
			for _, child := range children {
				if err := remove(filepath.Join(name, child)); err != nil {
					return err
				}
			}
		}
		disposition := byte(1)
		if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1); err != nil {
			return fmt.Errorf("remove %s: %w", name, err)
		}
		log("removed uncommitted 1.0 machine data: " + name)
		return nil
	}
	return remove(target)
}

// PrepareMachineUninstall recovers a certified stage before the legacy restore
// tool reads the live Undo record. A migration that could not recover Undo
// must not turn into a successful "nothing to undo" followed by deletion.
func PrepareMachineUninstall(path string, log func(string)) error {
	return prepareDirectory(path, log, nil, func(m directoryMarker) error {
		// This provenance survives a successful startup and repeated uninstall
		// attempts. Reading only this invocation's log would lose the warning.
		for _, note := range m.Notes {
			if strings.Contains(note, "WARNING:") || strings.Contains(note, "restored the validated Windows Undo backup") {
				log(note)
				return fmt.Errorf("Undo recovery is uncertain; retaining machine data and migration records")
			}
		}
		return nil
	})
}

func machineCleanupName(name, base string) bool {
	if strings.EqualFold(name, base) || strings.EqualFold(name, base+".migrating") {
		return true
	}
	for _, suffix := range []string{".untrusted-", ".migrating.untrusted-"} {
		prefix := base + suffix
		if len(name) == len(prefix)+24 && strings.EqualFold(name[:len(prefix)], prefix) {
			_, err := hex.DecodeString(name[len(prefix):])
			return err == nil
		}
	}
	return false
}

// CleanupMachineData runs only after restoration succeeds or the owner elects
// to discard Undo. Each entry is inspected and deleted through the same
// no-follow handle. No ownership, DACL or file attribute is ever rewritten.
func CleanupMachineData(path string, log func(string)) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := validateMachineLeaf(path, filepath.Base(path)); err != nil {
		return err
	}
	open := func(name string, access uint32) (*os.File, windows.ByHandleFileInformation, error) {
		var info windows.ByHandleFileInformation
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, info, err
		}
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil, info, err
		}
		f := os.NewFile(uintptr(h), name)
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			f.Close()
			return nil, info, err
		}
		return f, info, nil
	}
	// Pin every ancestor without following links, so a checked pathname
	// cannot be redirected while descendants are enumerated or deleted.
	var ancestors []string
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		ancestors = append(ancestors, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	var parent *os.File
	for i := len(ancestors) - 1; i >= 0; i-- {
		access := uint32(0)
		if i == 0 {
			access = windows.FILE_LIST_DIRECTORY
		}
		f, info, err := open(ancestors[i], access)
		if err != nil {
			return err
		}
		defer f.Close()
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("cleanup ancestor is not a plain directory: %s", ancestors[i])
		}
		parent = f
	}
	canonical, err := canonicalizeFromPinnedParent(windows.Handle(parent.Fd()), filepath.Base(path))
	if err != nil {
		return err
	}
	var problems []error
	var remove func(string) (bool, error)
	remove = func(name string) (bool, error) {
		// FILE_READ_DATA is FILE_LIST_DIRECTORY for directories. Refuse
		// inaccessible objects rather than taking ownership to delete them.
		f, info, err := open(name, windows.READ_CONTROL|windows.DELETE|windows.FILE_READ_DATA)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("retain %s: %w", name, err)
		}
		defer f.Close()
		h := windows.Handle(f.Fd())
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return false, err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return false, err
		}
		if owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
			log("retained non-admin-owned machine data: " + name)
			return false, nil
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
			// Ownership alone cannot authorize walking an attacker-writable
			// directory. Retained write handles also conflict with this open.
			if !trustedMachineSecurity(sd) {
				log("retained machine directory with untrusted permissions: " + name)
				return false, nil
			}
			names, err := f.Readdirnames(-1)
			if err != nil {
				return false, err
			}
			empty := true
			for _, child := range names {
				removed, err := remove(filepath.Join(name, child))
				if err != nil {
					problems = append(problems, err)
					log(err.Error())
				}
				empty = empty && removed
			}
			if !empty {
				return false, nil
			}
		}
		// FileDispositionInfo operates on the opened link itself. In
		// particular, never clear a hardlinked file's read-only attribute.
		disposition := byte(1)
		if err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1); err != nil {
			return false, fmt.Errorf("retain %s: safe deletion failed: %w", name, err)
		}
		log("removed machine data: " + name)
		return true, nil
	}
	names, err := parent.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if machineCleanupName(name, filepath.Base(canonical)) {
			if _, err := remove(filepath.Join(filepath.Dir(path), name)); err != nil {
				problems = append(problems, err)
				log(err.Error())
			}
		}
	}
	key, err := openDirectoryCertificates(true)
	if err != nil {
		return err
	}
	if storeTarget, _, sErr := key.GetStringValue("store-" + directoryCertificateName(canonical)); sErr == nil {
		if filepath.IsAbs(storeTarget) && strings.EqualFold(filepath.Dir(storeTarget), filepath.Dir(canonical)) {
			if _, rErr := remove(storeTarget); rErr != nil {
				problems = append(problems, rErr)
				log(rErr.Error())
			}
			_ = key.DeleteValue(directoryCertificateName(storeTarget))
		}
		_ = key.DeleteValue("store-" + directoryCertificateName(canonical))
	}
	err = key.DeleteValue(directoryCertificateName(canonical))
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		key.Close()
		return err
	}
	info, err := key.Stat()
	key.Close()
	if err != nil {
		return err
	}
	// Other explicitly configured machine-data folders share this key.
	if info.ValueCount == 0 && info.SubKeyCount == 0 {
		software, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE|registry.WOW64_64KEY)
		if err != nil {
			return err
		}
		defer software.Close()
		if err := registry.DeleteKey(software, strings.TrimPrefix(directoryCertificateKey, `SOFTWARE\`)); err != nil {
			return err
		}
		log("removed machine-folder certification key")
	} else {
		log("removed machine-folder certificate; other configured folders retained their certificates")
	}
	return errors.Join(problems...)
}
