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
)

// Spec §2: when the engine dies, apps must get the normal internet at once.
// An app's stream through the TUN terminates inside the engine's network
// stack, so nothing resets it when the engine goes; cleanup has to. On main
// (and on the first push of PR 2b) the ported Linux lifecycle suite sat on
// every such stream until its 10 s read deadline ("old stream was not closed
// when the engine died") in six cases, including lease lapse. This runs only
// in CI's isolated namespace: it destroys every socket bound to the test
// address, which must belong to nobody else.
func TestDestroyBoundSocketsEndsAppStreams(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const bound = "127.0.0.77"
	listener, err := net.Listen("tcp4", bound+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	datagram, err := net.ListenPacket("udp4", bound+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer datagram.Close()
	// A socket outside the prefix must survive untouched.
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	destroyed, err := destroyBoundSockets(ctx, netip.MustParsePrefix(bound+"/32"))
	if err != nil {
		t.Fatal(err)
	}
	// The listener, both ends of the stream and the datagram socket.
	if destroyed != 4 {
		t.Fatalf("destroyed %d sockets, want 4", destroyed)
	}
	for name, conn := range map[string]net.Conn{"client": client, "server": server} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		_, err := conn.Read(b[:])
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatalf("%s stream was not ended promptly: %v", name, err)
		}
	}
	datagram.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := datagram.ReadFrom(make([]byte, 16)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("datagram socket was not ended promptly", err)
	}
	if _, err := net.Dial("tcp4", other.Addr().String()); err != nil {
		t.Fatal("a socket outside the prefix was destroyed", err)
	}
}
