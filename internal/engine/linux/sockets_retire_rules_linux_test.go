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

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The rules of socket retirement, each on the pure decision code, so they hold
// without root. The first version compared prefixes, skipped the ownership
// checks cleanup applies, treated a failed address listing as "no other
// interfaces", forgot the journaled addresses once teardown removed them, and
// let the host listing run past the share.

func tcpRow(local, remote string, state uint8) socketRow {
	return socketRow{family: unix.AF_INET, protocol: unix.IPPROTO_TCP, state: state, local: netip.MustParseAddrPort(local), remote: netip.MustParseAddrPort(remote)}
}

func addr(cidr string) netlink.Addr {
	ip, n, _ := net.ParseCIDR(cidr)
	n.IP = ip
	return netlink.Addr{IPNet: n}
}

func TestRetirementSelectsTheExactJournaledAddressOnly(t *testing.T) {
	scope := newRetirementScope(map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true}, []netlink.Addr{addr("198.18.0.1/30"), addr("198.18.0.2/24")})
	if carried, _ := scope.carried(tcpRow("198.18.0.1:40000", "192.0.2.9:443", unix.BPF_TCP_ESTABLISHED)); !carried {
		t.Fatal("a connection on the journaled address to a remote peer was not selected")
	}
	// .2 lies in the TUN's /30 but is another interface's address.
	if carried, spared := scope.carried(tcpRow("198.18.0.2:40000", "192.0.2.9:443", unix.BPF_TCP_ESTABLISHED)); carried || spared {
		t.Fatal("a connection on another interface's address in the same subnet was selected")
	}
	// IPv4-mapped forms of the same address are the same address.
	if carried, _ := scope.carried(socketRow{family: unix.AF_INET6, protocol: unix.IPPROTO_TCP, state: unix.BPF_TCP_ESTABLISHED, local: netip.MustParseAddrPort("[::ffff:198.18.0.1]:40000"), remote: netip.MustParseAddrPort("[::ffff:192.0.2.9]:443")}); !carried {
		t.Fatal("the mapped form of the journaled address was not recognised")
	}
}

func TestRetirementIgnoresRecordsOfOtherBootsOrNamespaces(t *testing.T) {
	object := ObjectJSON(addressObject{Index: 7, Name: "ns0123456789", Alias: "netswitch:x", CIDR: "198.18.0.1/30"})
	record := func(boot, netns string) journal.Record {
		return journal.Record{ID: "a", Boot: boot, Instance: "x", Kind: "address", Phase: "created", Fingerprint: journal.Fingerprint{"boot": boot, "netns": netns, "object": object}}
	}
	if got := routedAddresses([]journal.Record{record("boot-1", "ns-1")}, "boot-1", "ns-1"); len(got) != 1 || !got[netip.MustParseAddr("198.18.0.1")] {
		t.Fatal("this boot's and namespace's record was not read", got)
	}
	for name, r := range map[string]journal.Record{
		"other boot":              record("boot-0", "ns-1"),
		"other namespace":         record("boot-1", "ns-2"),
		"no boot":                 record("", "ns-1"),
		"route, not address":      {ID: "r", Boot: "boot-1", Instance: "x", Kind: "route", Phase: "created", Fingerprint: journal.Fingerprint{"boot": "boot-1", "netns": "ns-1", "object": object}},
		"extra fingerprint field": {ID: "a", Boot: "boot-1", Instance: "x", Kind: "address", Phase: "created", Fingerprint: journal.Fingerprint{"boot": "boot-1", "netns": "ns-1", "object": object, "extra": "1"}},
	} {
		if got := routedAddresses([]journal.Record{r}, "boot-1", "ns-1"); len(got) != 0 {
			t.Fatalf("%s: record selected an address: %v", name, got)
		}
	}
}

func TestRetirementAbortsWhenHostAddressesAreUnknown(t *testing.T) {
	listHostAddresses = func() ([]netlink.Addr, error) { return nil, errors.New("netlink unavailable") }
	t.Cleanup(func() {
		listHostAddresses = func() ([]netlink.Addr, error) { return netlink.AddrList(nil, netlink.FAMILY_ALL) }
	})
	sockDestroyRequest = func(context.Context, *os.File, int, socketRow) error {
		t.Error("a destroy was sent with host addresses unknown")
		return nil
	}
	t.Cleanup(func() { sockDestroyRequest = sockDestroy })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := retireRoutedSocketsWithin(ctx, map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true})
	if out.err == nil || out.ended != 0 {
		t.Fatalf("unknown host addresses did not abort retirement: %+v", out)
	}
}

func TestRetirementKeepsRemovedTunAddressesLocal(t *testing.T) {
	// Teardown has already removed the TUN: the host list no longer has .1,
	// but the journal still names it, so a connection to it is local-only.
	tun := map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true}
	scope := newRetirementScope(tun, []netlink.Addr{addr("10.0.0.5/24")})
	if carried, spared := scope.carried(tcpRow("198.18.0.1:40000", "198.18.0.1:8080", unix.BPF_TCP_ESTABLISHED)); carried || !spared {
		t.Fatal("a local-only connection to the removed TUN address was selected")
	}
	if carried, spared := scope.carried(tcpRow("198.18.0.1:40000", "10.0.0.5:8080", unix.BPF_TCP_ESTABLISHED)); carried || !spared {
		t.Fatal("a connection to this host's other address was selected")
	}
	if carried, spared := scope.carried(tcpRow("198.18.0.1:40000", "127.0.0.1:8080", unix.BPF_TCP_ESTABLISHED)); carried || !spared {
		t.Fatal("a loopback connection was selected")
	}
}

func TestRetirementSparesListenersUnconnectedAndLinkLocalPeers(t *testing.T) {
	tun := map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true, netip.MustParseAddr("fdfe:dcba:9876::1"): true}
	scope := newRetirementScope(tun, []netlink.Addr{addr("fe80::1/64")})
	cases := map[string]socketRow{
		"listener":        tcpRow("198.18.0.1:8080", "0.0.0.0:0", unix.BPF_TCP_LISTEN),
		"time-wait":       tcpRow("198.18.0.1:40000", "192.0.2.9:443", unix.BPF_TCP_TIME_WAIT),
		"unconnected UDP": {family: unix.AF_INET, protocol: unix.IPPROTO_UDP, local: netip.MustParseAddrPort("198.18.0.1:5000"), remote: netip.MustParseAddrPort("0.0.0.0:0")},
		// The dump carries no scope for a link-local peer: this host's fe80::1
		// on one interface and a neighbour's fe80::1 on another look alike.
		"link-local peer":                      {family: unix.AF_INET6, protocol: unix.IPPROTO_TCP, state: unix.BPF_TCP_ESTABLISHED, local: netip.MustParseAddrPort("[fdfe:dcba:9876::1]:40000"), remote: netip.MustParseAddrPort("[fe80::1]:443"), ifindex: 3},
		"link-local peer on another interface": {family: unix.AF_INET6, protocol: unix.IPPROTO_TCP, state: unix.BPF_TCP_ESTABLISHED, local: netip.MustParseAddrPort("[fdfe:dcba:9876::1]:40000"), remote: netip.MustParseAddrPort("[fe80::2]:443"), ifindex: 4},
	}
	for name, row := range cases {
		if carried, spared := scope.carried(row); carried || !spared {
			t.Fatalf("%s was selected for destruction", name)
		}
	}
	if carried, _ := scope.carried(socketRow{family: unix.AF_INET6, protocol: unix.IPPROTO_UDP, local: netip.MustParseAddrPort("[fdfe:dcba:9876::1]:5000"), remote: netip.MustParseAddrPort("[2001:db8::9]:53")}); !carried {
		t.Fatal("a connected IPv6 datagram socket to a remote peer was not selected")
	}
}

func TestRetirementBoundsTheHostAddressListing(t *testing.T) {
	listHostAddresses = func() ([]netlink.Addr, error) { time.Sleep(2 * time.Second); return nil, nil }
	t.Cleanup(func() {
		listHostAddresses = func() ([]netlink.Addr, error) { return netlink.AddrList(nil, netlink.FAMILY_ALL) }
	})
	sockDestroyRequest = func(context.Context, *os.File, int, socketRow) error {
		t.Error("a destroy was sent after the listing ran out of time")
		return nil
	}
	t.Cleanup(func() { sockDestroyRequest = sockDestroy })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	began := time.Now()
	out := retireRoutedSocketsWithin(ctx, map[netip.Addr]bool{netip.MustParseAddr("198.18.0.1"): true})
	if !errors.Is(out.err, context.DeadlineExceeded) || out.ended != 0 {
		t.Fatalf("slow listing did not end retirement: %+v", out)
	}
	if time.Since(began) > 500*time.Millisecond {
		t.Fatal("retirement waited for the slow listing", time.Since(began))
	}
}
