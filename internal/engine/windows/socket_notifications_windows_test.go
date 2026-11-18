//go:build windows

package winengine

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func TestSocketStateLevelsAndRemovalOnLoopback(t *testing.T) {
	if err := stateProc.Find(); err != nil {
		t.Skip("socket state notifications unavailable on this Windows build")
	}
	q, err := newStateQueue()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := q.close(); err != nil {
			t.Error(err)
		}
	}()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h, err := windows.WSASocket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		t.Fatal(err)
	}
	s := winhandle.Open(h, "loopback socket state test")
	defer s.SocketClose("loopback socket state test close")
	if err := windows.Connect(s.Handle("loopback connect"), &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: ln.Addr().(*net.TCPAddr).Port}); err != nil {
		t.Fatal(err)
	}
	peer, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := setNonblocking(s, "loopback receive"); err != nil {
		t.Fatal(err)
	}
	wakeup := make(chan struct{}, 1)
	w, err := q.watch(&socketWatch{socket: s}, func() {
		select {
		case wakeup <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Detach()
	arm := func() {
		t.Helper()
		if err := w.Arm(true, false); err != nil {
			t.Fatal(err)
		}
		select {
		case <-wakeup:
		case <-time.After(time.Second):
			t.Fatal("missing read notification")
		}
	}
	if _, err := peer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	arm()
	var data [3]byte
	if n, err := socketIOFlags(s, "recv", data[:], 2); n != 3 || err != nil {
		t.Fatalf("peek %d %v", n, err)
	}
	arm()
	if n, err := socketIO(s, "recv", data[:]); n != 3 || err != nil || string(data[:]) != "abc" {
		t.Fatalf("read %d %q %v", n, data, err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	arm()
	if n, err := socketIO(s, "recv", data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("terminal read %d %v", n, err)
	}
	w.Detach()
	if err := w.Arm(true, false); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-remove arm %v", err)
	}
}
