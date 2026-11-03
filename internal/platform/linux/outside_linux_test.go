//go:build linux

package linuxplatform

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"golang.org/x/sys/unix"
)

func TestLinuxKernelLayoutsAndConstants(t *testing.T) {
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"AF_INET", unix.AF_INET, linuxAFInet},
		{"AF_INET6", unix.AF_INET6, linuxAFInet6},
		{"IPPROTO_TCP", unix.IPPROTO_TCP, linuxIPProtoTCP},
		{"TCPInfo.Bytes_acked", unsafe.Offsetof(unix.TCPInfo{}.Bytes_acked), tcpInfoBytesAckedOffset},
		{"TCPInfo.Bytes_received", unsafe.Offsetof(unix.TCPInfo{}.Bytes_received), tcpInfoBytesReceivedOffset},
		{"TCPInfo.Bytes_sent", unsafe.Offsetof(unix.TCPInfo{}.Bytes_sent), tcpInfoBytesSentOffset},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestParseOutsideArgs(t *testing.T) {
	engine, once, err := ParseOutsideArgs([]string{"--engine", "/usr/lib/netswitch/netswitch-engine", "--once", "--parent", "123"})
	if err != nil || engine != "/usr/lib/netswitch/netswitch-engine" || !once {
		t.Fatalf("ParseOutsideArgs valid = (%q, %v, %v)", engine, once, err)
	}
	if _, _, err := ParseOutsideArgs([]string{"extra"}); err == nil {
		t.Fatal("accepted unexpected positional argument")
	}
	if _, _, err := ParseOutsideArgs([]string{"--parent", "99999999999"}); err == nil {
		t.Fatal("accepted out-of-range --parent")
	}
}

func openMeasuredPair(t *testing.T, network, listenAddr string) (client, server net.Conn, local, remote netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen(network, listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := net.DialTimeout("tcp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := <-accepted
	t.Cleanup(func() { s.Close() })

	lAddr := c.LocalAddr().(*net.TCPAddr)
	rAddr := c.RemoteAddr().(*net.TCPAddr)
	return c, s, lAddr.AddrPort(), rAddr.AddrPort()
}

func exchangeExact(t *testing.T, client, server net.Conn, upBytes, downBytes int) {
	t.Helper()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	server.SetDeadline(time.Now().Add(5 * time.Second))
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, upBytes)
		if _, err := io.ReadFull(server, buf); err != nil {
			errCh <- err
			return
		}
		_, err := server.Write(bytes.Repeat([]byte("d"), downBytes))
		errCh <- err
	}()
	if _, err := client.Write(bytes.Repeat([]byte("u"), upBytes)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, downBytes)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestLiveSockDiagTCPInfoAndProcOwners(t *testing.T) {
	c4, s4, local4, remote4 := openMeasuredPair(t, "tcp4", "127.0.0.1:0")
	exchangeExact(t, c4, s4, 4096, 2048)

	// Dual-stack listener on [::]:0 accepts an IPv4 client as an AF_INET6 ::ffff:127.0.0.1 socket.
	var hasV6 bool
	var s6Local, s6Remote netip.AddrPort
	if ln6, err := net.Listen("tcp", "[::]:0"); err == nil {
		defer ln6.Close()
		var dualVal, errOpt = unix.GetsockoptInt(mustListenerFD(t, ln6), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		if errOpt == nil && dualVal == 0 {
			hasV6 = true
			port6 := uint16(ln6.Addr().(*net.TCPAddr).Port)
			accepted := make(chan net.Conn, 1)
			go func() {
				if conn, err := ln6.Accept(); err == nil {
					accepted <- conn
				}
			}()
			c6, err := net.DialTimeout("tcp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port6).String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c6.Close()
			s6 := <-accepted
			defer s6.Close()
			exchangeExact(t, c6, s6, 3000, 1500)
			// Server side s6 is AF_INET6 with ::ffff:127.0.0.1 endpoints!
			s6Local = netip.AddrPortFrom(s6.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(), uint16(s6.LocalAddr().(*net.TCPAddr).Port))
			s6Remote = netip.AddrPortFrom(s6.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(), uint16(s6.RemoteAddr().(*net.TCPAddr).Port))
		}
	}

	rows, err := dumpEstablishedTCP(netip.AddrPort{}, netip.AddrPort{}, true)
	if err != nil {
		t.Fatal(err)
	}
	var found4, found6 *diagSocket
	for i := range rows {
		r := &rows[i]
		if r.local == local4 && r.remote == remote4 {
			found4 = r
		}
		if hasV6 && r.local == s6Local && r.remote == s6Remote && r.family == unix.AF_INET6 {
			found6 = r
		}
	}
	if found4 == nil {
		t.Fatalf("live AF_INET socket %s -> %s not found in sock_diag dump", local4, remote4)
	}
	if !found4.measured || found4.up < 4096 || found4.down < 2048 || found4.cookie == 0 || found4.inode == 0 {
		t.Fatalf("unexpected AF_INET sock_diag metrics: %+v", *found4)
	}
	if hasV6 {
		if found6 == nil {
			t.Fatalf("live dual-stack AF_INET6 ::ffff: socket %s -> %s not found in sock_diag dump", s6Local, s6Remote)
		}
		if !found6.measured || found6.down < 3000 || found6.up < 1500 || found6.cookie == 0 || found6.inode == 0 {
			t.Fatalf("unexpected AF_INET6 mapped sock_diag metrics: %+v", *found6)
		}
	}

	// Send additional payload and verify single-socket diagReadOne observes the delta.
	exchangeExact(t, c4, s4, 1024, 512)
	downAfter, upAfter, ok := diagReadOne(*found4)
	if !ok || downAfter < found4.down+512 || upAfter < found4.up+1024 {
		t.Fatalf("diagReadOne(%+v) = (%d, %d, %v), want >= (%d, %d)", *found4, downAfter, upAfter, ok, found4.down+512, found4.up+1024)
	}

	myPID := uint32(os.Getpid())
	myStart, err := readProcStatStart(myPID)
	if err != nil || myStart == 0 {
		t.Fatalf("readProcStatStart(self) = (%d, %v)", myStart, err)
	}
	myExe := readProcExe(myPID)
	owners := scanSocketOwners(map[uint32]struct{}{found4.inode: {}})
	owner := owners[found4.inode]
	if owner.pid != myPID || owner.start != myStart || owner.path == "" || owner.path != myExe {
		t.Fatalf("scanSocketOwners = %+v, want pid=%d start=%d path=%q", owner, myPID, myStart, myExe)
	}
	held, err := pidHoldsSocketInode(myPID, found4.inode)
	if err != nil || !held {
		t.Fatalf("pidHoldsSocketInode = (%v, %v)", held, err)
	}
}

func mustListenerFD(t *testing.T, ln net.Listener) int {
	t.Helper()
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := raw.Control(func(s uintptr) { fd = int(s) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestLiveCloseTCP(t *testing.T) {
	c, s, local, remote := openMeasuredPair(t, "tcp4", "127.0.0.1:0")
	exchangeExact(t, c, s, 64, 64)

	myPID := uint32(os.Getpid())
	myStart, err := readProcStatStart(myPID)
	if err != nil {
		t.Fatal(err)
	}
	sock, found, err := findEstablishedSocket(context.Background(), local, remote, 0)
	if err != nil || !found {
		t.Fatalf("findEstablishedSocket = (%+v, %v, %v)", sock, found, err)
	}

	makeSelector := func(start uint64, cookie uint64) platform.TCPSelector {
		return platform.TCPSelector{
			Tuple: apps.Tuple{
				Local:   local.Addr().String(),
				LPort:   float64(local.Port()),
				Remote:  remote.Addr().String(),
				RPort:   float64(remote.Port()),
				PID:     float64(myPID),
				Created: "2026-11-03T12:00:00.0000000Z",
			},
			ProcessStarted: formatProcessStarted(start, cookie),
		}
	}

	// Mismatched starttime or cookie must report gone and leave the live socket intact.
	for _, bad := range []platform.TCPSelector{
		makeSelector(myStart+1, sock.cookie),
		makeSelector(myStart, sock.cookie^1),
	} {
		res, err := CloseTCP(context.Background(), map[string]any{"connections": []platform.TCPSelector{bad}})
		if err != nil || res["gone"] != 1 || res["closed"] != 0 || res["failed"] != 0 {
			t.Fatalf("mismatch CloseTCP = %+v, %v", res, err)
		}
		exchangeExact(t, c, s, 32, 32)
	}

	if os.Geteuid() != 0 {
		t.Skip("SOCK_DESTROY requires CAP_NET_ADMIN; live abort verified in elevated CI")
	}

	res, err := CloseTCP(context.Background(), map[string]any{"connections": []platform.TCPSelector{makeSelector(myStart, sock.cookie)}})
	if err != nil {
		t.Fatal(err)
	}
	if res["reason"] == "not supported here" {
		t.Log("kernel lacks CONFIG_INET_DIAG_DESTROY; verified 'not supported here' response")
		return
	}
	if res["closed"] != 1 || res["failed"] != 0 || res["gone"] != 0 {
		t.Fatalf("root CloseTCP = %+v", res)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := c.Read(one[:]); err == nil {
		t.Fatal("destroyed TCP socket remained readable")
	}

	// Repeating CloseTCP on the now-destroyed socket must report gone: 1.
	again, err := CloseTCP(context.Background(), map[string]any{"connections": []platform.TCPSelector{makeSelector(myStart, sock.cookie)}})
	if err != nil || again["gone"] != 1 || again["closed"] != 0 || again["failed"] != 0 {
		t.Fatalf("repeat CloseTCP = %+v, %v", again, err)
	}
}
