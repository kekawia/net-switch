//go:build !windows

package lifecycle

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func createUpdateToolFile(path string, bytes []byte, secret bool) error {
	mode := os.FileMode(0644)
	if secret {
		mode = 0600
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(bytes)
	syncErr, closeErr := f.Sync(), f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

func openUpdateToolInput(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 {
		f.Close()
		return nil, errors.New("signing input must be a plain single-link file")
	}
	return f, nil
}
