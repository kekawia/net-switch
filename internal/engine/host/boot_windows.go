package host

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// BootGUID is this boot's identity: the BootIdentifier of
// SystemBootEnvironmentInformation, new on every boot.
func BootGUID() (windows.GUID, error) {
	var info struct {
		ID       windows.GUID
		Firmware uint32
		Flags    uint64
	}
	var size uint32
	if err := windows.NtQuerySystemInformation(windows.SystemBootEnvironmentInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &size); err != nil {
		return windows.GUID{}, err
	}
	return info.ID, nil
}

// CurrentBootID is BootGUID as 32 hex digits, the form outcomes carry on
// Linux too. On Windows it only binds an outcome to its boot, so a host whose
// service was re-registered can still prove a clean stop. Without it that
// exit stays unknown, as before, and the engine still runs.
func CurrentBootID() (string, error) {
	g, err := BootGUID()
	if err != nil {
		return "", nil
	}
	id := fmt.Sprintf("%08x%04x%04x%x", g.Data1, g.Data2, g.Data3, g.Data4[:])
	if !ValidInvocationID(id) {
		return "", nil
	}
	return id, nil
}
