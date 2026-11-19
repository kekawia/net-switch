package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

// COMInterface is the vtable layout shared by the Automation and WinRT readers.
type COMInterface struct{ VT *[32]uintptr }

type COMError struct{ Code uint32 }

func (e *COMError) Error() string { return fmt.Sprintf("COM HRESULT 0x%08x", e.Code) }

func HRESULT(hr uintptr) error {
	if int32(uint32(hr)) < 0 {
		return &COMError{Code: uint32(hr)}
	}
	return nil
}

//go:uintptrescapes
func (o *COMInterface) InvokeSlot(slot int, args ...uintptr) (uintptr, error) {
	all := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	r, _, _ := syscall.SyscallN(o.VT[slot], all...)
	return r, HRESULT(r)
}

func (o *COMInterface) Release() {
	if o != nil {
		_, _ = o.InvokeSlot(2)
	}
}
