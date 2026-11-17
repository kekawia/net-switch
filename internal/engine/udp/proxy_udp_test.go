package udp

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/kekawia/net-switch/internal/engine/testfake"
)

type countingController struct {
	testfake.Controller
	mu              sync.Mutex
	lineErrors      []string
	unsupportedLine map[string]uint64
	unsupportedApp  map[string]uint64
}

func (c *countingController) LineError(line string, _ error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lineErrors = append(c.lineErrors, line)
}

func (c *countingController) UnsupportedUDP(line, app string, packets uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unsupportedLine == nil {
		c.unsupportedLine = map[string]uint64{}
		c.unsupportedApp = map[string]uint64{}
	}
	c.unsupportedLine[line] += packets
	c.unsupportedApp[app] += packets
}

func TestUnsupportedUDPRefusesWithICMPWithoutLineErrorAndCountsFollowUps(t *testing.T) {
	ctrl := &countingController{Controller: testfake.Controller{Line: "http-proxy"}}
	out := make(chan []byte, 64)
	ids := &identity{value: owner}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		return nil, platform.ErrUnsupportedUDP
	}}
	n := New(context.Background(), nil, ctrl, &testfake.Owners{Value: owner}, ids, d, testfake.Output{Packets: out}, 1500)
	t.Cleanup(n.Close)

	// Initial datagram triggers setup -> ErrUnsupportedUDP -> ICMP unreachable.
	send(n, dest, []byte("quic-initial"))
	icmp1 := await(t, out)
	if len(icmp1) < 28 || icmp1[9] != 1 { // IPv4 protocol 1 = ICMP
		t.Fatalf("expected ICMP unreachable reply for packet 1, got %d bytes proto=%d", len(icmp1), icmp1[9])
	}

	// Follow-up datagrams within negative-cache window also get ICMP unreachable and count in UnsupportedUDP.
	send(n, dest, []byte("quic-retry-1"))
	icmp2 := await(t, out)
	if len(icmp2) < 28 || icmp2[9] != 1 {
		t.Fatalf("expected ICMP unreachable reply for packet 2")
	}

	ctrl.mu.Lock()
	lineErrs := len(ctrl.lineErrors)
	lineCount := ctrl.unsupportedLine["http-proxy"]
	appCount := ctrl.unsupportedApp[owner.AppID]
	ctrl.mu.Unlock()

	if lineErrs != 0 {
		t.Fatalf("ErrUnsupportedUDP must not trigger LineError, got %d", lineErrs)
	}
	if n.OpenFailed.Load() != 0 {
		t.Fatalf("ErrUnsupportedUDP must not increment OpenFailed, got %d", n.OpenFailed.Load())
	}
	if n.UnsupportedUDP.Load() != 2 || lineCount != 2 || appCount != 2 {
		t.Fatalf("UnsupportedUDP counts = (nat=%d, line=%d, app=%d), want (2, 2, 2)", n.UnsupportedUDP.Load(), lineCount, appCount)
	}
}

type droppingSocket struct {
	*socket
	drops int
}

func (d *droppingSocket) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if d.drops > 0 {
		d.drops--
		_, _, _ = d.socket.ReadFrom(b)
		return 0, netip.AddrPort{}, platform.ErrDatagramDropped
	}
	return d.socket.ReadFrom(b)
}

func TestDatagramDroppedSkipsReadRetryBackoff(t *testing.T) {
	c := &testfake.Controller{Line: "socks5"}
	out := make(chan []byte, 16)
	ids := &identity{value: owner}
	base := newSocket()
	ds := &droppingSocket{socket: base, drops: 3}
	d := testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		return ds, nil
	}}
	n := New(context.Background(), nil, c, &testfake.Owners{Value: owner}, ids, d, testfake.Output{Packets: out}, 1500)
	t.Cleanup(n.Close)

	send(n, dest, []byte("hello"))
	await(t, base.out)

	start := time.Now()
	base.in <- wire{[]byte("spoof1"), dest}
	base.in <- wire{[]byte("spoof2"), dest}
	base.in <- wire{[]byte("spoof3"), dest}
	base.in <- wire{[]byte("legit"), dest}
	await(t, out)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("spoofed/dropped datagrams stalled legitimate UDP reply for %v", elapsed)
	}
	if n.Dropped.Load() != 3 || n.ReadErrors.Load() != 0 {
		t.Fatalf("Dropped=%d ReadErrors=%d, want (3, 0)", n.Dropped.Load(), n.ReadErrors.Load())
	}
}
