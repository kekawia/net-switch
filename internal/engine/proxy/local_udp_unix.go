//go:build !windows

package proxy

import (
	"errors"
	"syscall"
)

func waitLoopbackUDPReadable(raw syscall.RawConn) error {
	var readErr error
	var peek [1]byte
	err := raw.Read(func(fd uintptr) bool {
		for {
			_, _, readErr = syscall.Recvfrom(int(fd), peek[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			if readErr == syscall.EINTR {
				continue
			}
			return readErr != syscall.EAGAIN && readErr != syscall.EWOULDBLOCK
		}
	})
	return errors.Join(err, readErr)
}
