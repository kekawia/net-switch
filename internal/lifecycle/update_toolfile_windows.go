package lifecycle

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createUpdateToolFile(path string, bytes []byte, secret bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var sa *windows.SecurityAttributes
	if secret {
		user := CurrentUser()
		if user == "" {
			return errors.New("cannot determine key owner")
		}
		sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)")
		if err != nil {
			return err
		}
		sa = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	_, writeErr := f.Write(bytes)
	syncErr, closeErr := f.Sync(), f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

func openUpdateToolInput(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, errors.New("signing input must be a plain single-link file")
	}
	return os.NewFile(uintptr(h), path), nil
}
