//go:build windows

package proxy

import "syscall"

// waitLoopbackUDPReadable waits in Go's IOCP netpoller without consuming the
// queued datagram. On Windows, returning false from the first RawConn.Read
// callback makes internal/poll.(*FD).RawRead execute an overlapped zero-byte
// WSARecv(MSG_PEEK), which wakes on both empty and non-empty datagrams and
// honors SetReadDeadline and Close.
func waitLoopbackUDPReadable(raw syscall.RawConn) error {
	waited := false
	return raw.Read(func(uintptr) bool {
		if !waited {
			waited = true
			return false
		}
		return true
	})
}
