//go:build linux

package linux

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestChooseBandBothStartOrdersAndReconnectCycles(t *testing.T) {
	// 1. Clean machine -> standardBand(14000) leaves [1..23049] headroom.
	b0, ok := chooseBand(ruleBand{}, nil, nil)
	if !ok || b0 != standardBand(14000) {
		t.Fatalf("expected standardBand(14000), got %+v ok=%v", b0, ok)
	}

	// 2. Tailscale split-tunnel (table 52 has 100.64.0.0/10 only, no default):
	// must NOT trigger step-down below 5270.
	tsRoutes := []netlink.Route{
		{Family: unix.AF_INET, Table: 52, Type: unix.RTN_UNICAST, Dst: prefix("100.64.0.0/10")},
	}
	tsRules := []netlink.Rule{
		{Priority: 5210, Mark: 0x80000, Table: unix.RT_TABLE_MAIN},
		{Priority: 5270, Table: 52},
	}
	defs := foreignDefaultTables(0, tsRoutes)
	if defs[52] {
		t.Fatal("split-only Tailscale table 52 treated as full-tunnel default table")
	}
	bTS, ok := chooseBand(b0, tsRules, defs)
	if !ok || bTS != standardBand(14000) {
		t.Fatalf("expected standardBand(14000) with split-only Tailscale, got %+v ok=%v", bTS, ok)
	}

	// 3. Engine starts first at standardBand(14000) (lowest prio 23050), then
	// wg-quick starts without pref -> kernel assigns 23049 -> engine steps down
	// above 23049; when wg-quick stops, engine restores standardBand(14000).
	// Repeat 100 times to prove zero priority drift.
	cur := b0
	for i := range 100 {
		wgPrio := cur.fwmarkBypass - 1
		wgRules := []netlink.Rule{{Priority: wgPrio, Mark: 0xca6c, Invert: true, Table: 51820}}
		wgRoutes := []netlink.Route{{Family: unix.AF_INET, Table: 51820, Type: unix.RTN_UNICAST, Dst: prefix("0.0.0.0/0")}}
		cur, ok = chooseBand(cur, wgRules, foreignDefaultTables(0, wgRoutes))
		if !ok || cur.capture >= wgPrio {
			t.Fatalf("cycle %d: failed to step above wg-quick (%d): got %+v ok=%v", i, wgPrio, cur, ok)
		}
		// wg-quick stops:
		cur, ok = chooseBand(cur, nil, nil)
		if !ok || cur != standardBand(14000) {
			t.Fatalf("cycle %d: failed to restore headroom after wg-quick stop: got %+v ok=%v", i, cur, ok)
		}
	}

	// 4. Tailscale + wg-quick (wg-quick gets 5209) or Tailscale Exit Node (5270):
	// compactBand places entire hierarchy cleanly below 5209.
	lowRules := append([]netlink.Rule{}, tsRules...)
	lowRules = append(lowRules, netlink.Rule{Priority: 5209, Mark: 0xca6c, Invert: true, Table: 51820})
	lowRoutes := append([]netlink.Route{}, tsRoutes...)
	lowRoutes = append(lowRoutes,
		netlink.Route{Family: unix.AF_INET, Table: 51820, Type: unix.RTN_UNICAST, Dst: prefix("0.0.0.0/1")},
		netlink.Route{Family: unix.AF_INET, Table: 51820, Type: unix.RTN_UNICAST, Dst: prefix("128.0.0.0/1")},
	)
	bLow, ok := chooseBand(b0, lowRules, foreignDefaultTables(0, lowRoutes))
	if !ok || bLow.capture >= 5209 || bLow.fwmarkBypass <= 0 {
		t.Fatalf("expected compact band below 5209, got %+v ok=%v", bLow, ok)
	}
}

func TestForeignMarkAndSplitTunnelBypassRules(t *testing.T) {
	band := standardBand(14000)
	ownMask := ^uint32(0)
	tsMask := uint32(0xff0000)
	rules := []netlink.Rule{
		{Family: unix.AF_INET, Priority: 32764, Mark: 0xca6c, Invert: true, Table: 51820},
		{Family: unix.AF_INET, Priority: 10001, Mark: 0x4e530001, Mask: &ownMask, Table: 21001},
		{Family: unix.AF_INET, Priority: 5210, Mark: 0x80000, Mask: &tsMask, Table: unix.RT_TABLE_MAIN},
	}
	bypassMarks := foreignMarkBypassRules(band, []int{unix.AF_INET, unix.AF_INET6}, rules)
	if len(bypassMarks) != 1 || bypassMarks[0].Mark != 0xca6c || bypassMarks[0].Priority != band.fwmarkBypass || bypassMarks[0].Table != unix.RT_TABLE_MAIN {
		t.Fatalf("unexpected foreignMarkBypassRules at 14000: %+v", bypassMarks)
	}

	// When stepped below 5210 (compactBand(5000)), Tailscale's 5210 fwmark->main
	// rule is also mirrored at fwmarkBypass so tailscaled's outer UDP bypasses TUN.
	lowBand := compactBand(5000)
	bypassLow := foreignMarkBypassRules(lowBand, []int{unix.AF_INET}, rules)
	if len(bypassLow) != 2 {
		t.Fatalf("expected both 0xca6c and 0x80000 mirrored when below 5210, got %+v", bypassLow)
	}

	wgCorp := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Index: 9, Name: "wg-corp", Flags: net.FlagUp | net.FlagPointToPoint}}
	wgLine := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Index: 10, Name: "wg-line", Flags: net.FlagUp | net.FlagPointToPoint}}
	ownTun := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Index: 11, Name: "netswitch0", Flags: net.FlagUp}}
	foreignRoutes := []netlink.Route{
		// Public corporate subnet on unconfigured tunnel -> must bypass capture.
		{Family: unix.AF_INET, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 9, Dst: prefix("198.51.100.0/24")},
		// Already covered by RFC1918 bypass -> skipped.
		{Family: unix.AF_INET, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 9, Dst: prefix("10.20.0.0/16")},
		// Default /1 split route -> skipped (not a split-subnet route).
		{Family: unix.AF_INET, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 9, Dst: prefix("0.0.0.0/1")},
		// Configured VPN line -> skipped.
		{Family: unix.AF_INET, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 10, Dst: prefix("203.0.113.0/24")},
		// Engine's own TUN -> skipped.
		{Family: unix.AF_INET, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, LinkIndex: 11, Dst: prefix("198.18.0.0/30")},
	}
	splitRules := splitTunnelBypassRules(band, []netlink.Link{wgCorp, wgLine, ownTun}, map[int]bool{10: true}, 11, foreignRoutes, false)
	if len(splitRules) != 1 || splitRules[0].Dst.String() != "198.51.100.0/24" || splitRules[0].Priority != band.splitBypass {
		t.Fatalf("unexpected splitTunnelBypassRules: %+v", splitRules)
	}

	var sa4 [16]byte
	binary.NativeEndian.PutUint16(sa4[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(sa4[2:4], 51820)
	copy(sa4[4:8], []byte{192, 0, 2, 13})
	ep4, ok := parseWGPeerEndpoint(sa4[:])
	if !ok || ep4 != netip.MustParseAddr("192.0.2.13") {
		t.Fatalf("parseWGPeerEndpoint(v4) = (%v, %v), want 192.0.2.13", ep4, ok)
	}

	var sa6 [28]byte
	binary.NativeEndian.PutUint16(sa6[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(sa6[2:4], 51820)
	ip6 := netip.MustParseAddr("2001:db8::13").As16()
	copy(sa6[8:24], ip6[:])
	ep6, ok := parseWGPeerEndpoint(sa6[:])
	if !ok || ep6 != netip.MustParseAddr("2001:db8::13") {
		t.Fatalf("parseWGPeerEndpoint(v6) = (%v, %v), want 2001:db8::13", ep6, ok)
	}

	epRules := unmarkedWireGuardEndpointRules(band, []netip.Addr{
		ep4,
		ep4, // duplicate
		ep6,
		netip.MustParseAddr("127.0.0.1"),  // loopback -> skipped
		netip.MustParseAddr("10.0.0.5"),   // covered by RFC1918 bypass -> skipped
		netip.MustParseAddr("100.64.1.2"), // covered by CGNAT bypass -> skipped
	}, false)
	if len(epRules) != 2 || epRules[0].Dst.String() != "192.0.2.13/32" || epRules[1].Dst.String() != "2001:db8::13/128" {
		t.Fatalf("unexpected unmarkedWireGuardEndpointRules: %+v", epRules)
	}
	epRulesV4Only := unmarkedWireGuardEndpointRules(band, []netip.Addr{ep4, ep6}, true)
	if len(epRulesV4Only) != 1 || epRulesV4Only[0].Dst.String() != "192.0.2.13/32" {
		t.Fatalf("unexpected unmarkedWireGuardEndpointRules(ipv4Only): %+v", epRulesV4Only)
	}
}
