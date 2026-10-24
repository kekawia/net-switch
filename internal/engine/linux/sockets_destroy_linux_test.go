//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Spec §2, "failing open also ends connections the engine was carrying": the
// rule is connected sockets on a journaled TUN address with a non-local peer;
// listeners, unconnected UDP sockets and local-only connections survive. The
// ported Linux lifecycle suite sat on every routed stream until its read
// deadline in six cases, lease lapse included, because nothing ended them.
// This runs only in CI's isolated namespace, where the addresses it uses
// belong to nobody else.
func TestRoutedSocketRetirementFollowsTheSpecRule(t *testing.T) {
	ctx, tun := isolatedTunLike(t)
	// Connected sockets with non-local peers: a TCP handshake in flight to a
	// peer that never answers, and connected UDP in both families.
	dialed := make(chan error, 1)
	go func() {
		_, err := (&net.Dialer{Timeout: 20 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.18.0.1")}}).Dial("tcp4", "192.0.2.9:9")
		dialed <- err
	}()
	waitForState(t, unix.AF_INET, unix.IPPROTO_TCP, netip.MustParseAddr("198.18.0.1"), unix.BPF_TCP_SYN_SENT)
	udp4, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1")}, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer udp4.Close()
	udp6, err := net.DialUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fdfe:dcba:9876::1")}, &net.UDPAddr{IP: net.ParseIP("2001:db8::9"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer udp6.Close()
	// Spared: a listener on the TUN address, a local-only connection to it
	// from this host's other address, a connection bound to that other
	// address (in the TUN's subnet, not the journaled address), an
	// unconnected UDP socket, and loopback.
	listener, err := net.Listen("tcp4", "198.18.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	localConn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.18.0.2")}}).Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer localConn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	neighbour, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2")}, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer neighbour.Close()
	unconnected, err := net.ListenPacket("udp4", "198.18.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unconnected.Close()
	loopback, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Close()
	out := retireRoutedSocketsWithin(ctx, tun)
	if out.err != nil {
		t.Fatal(out.err)
	}
	if out.ended != 3 {
		t.Fatalf("ended %d connections, want 3 (TCP SYN_SENT, UDP v4, UDP v6); spared %d", out.ended, out.spared)
	}
	select {
	case err := <-dialed:
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatal("handshake to a dead peer was not ended", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake to a dead peer still pending after retirement")
	}
	for name, conn := range map[string]net.Conn{"udp4": udp4, "udp6": udp6} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(make([]byte, 16)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("connected %s socket to a non-local peer was not ended: %v", name, err)
		}
	}
	if _, err := net.Dial("tcp4", listener.Addr().String()); err != nil {
		t.Fatal("listener on the TUN address was destroyed", err)
	}
	for name, conn := range map[string]net.Conn{"local-only connection": localConn, "connection on the neighbouring address": neighbour} {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s was destroyed: %v", name, err)
		}
	}
	unconnected.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := unconnected.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("unconnected UDP socket was destroyed", err)
	}
	if _, err := net.Dial("tcp4", loopback.Addr().String()); err != nil {
		t.Fatal("loopback listener was destroyed", err)
	}
}

// Best effort inside its share: a refused or unsupported destruction ends the
// pass after one request, and a table larger than the bound ends the dump
// without hanging; both leave the mandatory cleanup its time.
func TestRoutedSocketRetirementIsBoundedAndStopsWhenRefused(t *testing.T) {
	ctx, tun := isolatedTunLike(t)
	var sockets []*net.UDPConn
	for i := 0; i < 5; i++ {
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1")}, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 100 + i})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		sockets = append(sockets, c)
	}
	attempts := 0
	sockDestroyRequest = func(context.Context, *os.File, int, socketRow) error { attempts++; return unix.EOPNOTSUPP }
	t.Cleanup(func() { sockDestroyRequest = sockDestroy })
	began := time.Now()
	out := retireRoutedSocketsWithin(ctx, tun)
	if attempts != 1 || out.ended != 0 || out.err == nil || !errors.Is(out.err, unix.EOPNOTSUPP) {
		t.Fatalf("unsupported destruction did not stop after one request: attempts=%d %+v", attempts, out)
	}
	if time.Since(began) > time.Second {
		t.Fatal("unsupported destruction consumed the budget", time.Since(began))
	}
	sockDestroyRequest = sockDestroy
	old := socketDumpMaxMatches
	socketDumpMaxMatches = 2
	t.Cleanup(func() { socketDumpMaxMatches = old })
	out = retireRoutedSocketsWithin(ctx, tun)
	if !errors.Is(out.err, errSocketDumpBounded) || out.ended != 2 {
		t.Fatalf("bounded dump: %+v", out)
	}
	socketDumpMaxMatches = old
	// A deadline already spent leaves nothing for retirement, and says so.
	spent, cancel := context.WithDeadline(ctx, time.Now())
	defer cancel()
	if out := retireRoutedSocketsWithin(spent, tun); out.err == nil {
		t.Fatal("retirement ran past an exhausted deadline", out)
	}
}

// isolatedTunLike gives the isolated namespace a dummy device shaped like the
// engine's TUN (198.18.0.1/30 plus a second host address, fdfe:dcba:9876::1)
// and device routes for the test peers, so handshakes and datagrams leave
// with the TUN source and are never answered. It returns the journaled TUN
// addresses as retirement would read them.
func isolatedTunLike(t *testing.T) (context.Context, map[netip.Addr]bool) {
	t.Helper()
	if os.Getenv("NETSWITCH_ISOLATED_NETNS") != "1" {
		t.Skip("requires CI's isolated network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated kernel test requires root")
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ns-retire0"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	for _, cidr := range []string{"198.18.0.1/30", "198.18.0.2/30", "fdfe:dcba:9876::1/126"} {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefix(cidr), Flags: unix.IFA_F_NODAD}); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"192.0.2.0/24", "2001:db8::/64"} {
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefix(cidr), Scope: netlink.SCOPE_LINK}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx, map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true, netip.MustParseAddr("fdfe:dcba:9876::1"): true}
}

func waitForState(t *testing.T, family, protocol int, local netip.Addr, state uint8) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := scanSockets(context.Background(), family, protocol, func(r socketRow) bool { return r.local.Addr() == local && r.state == state })
		if err == nil && len(rows) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %d/%d socket on %s reached state %d", family, protocol, local, state)
}
