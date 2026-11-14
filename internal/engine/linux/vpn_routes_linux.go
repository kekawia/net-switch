//go:build linux

package linux

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ruleBand holds the kernel fib_rule priorities for one active engine rule band.
// Separating ruleBand from slotBase lets the engine step its rules above a
// full-tunnel VPN rule (such as wg-quick or an exit node) in either start order
// while keeping every line's table (21000+slotBase+n) and SO_MARK
// (0x4e530000+slotBase+n) unchanged for live flows.
type ruleBand struct {
	fwmarkBypass int
	localBypass  int
	splitBypass  int
	markBase     int
	srcBase      int
	capture      int
}

func standardBand(base int) ruleBand {
	return ruleBand{
		fwmarkBypass: base + 9050,
		localBypass:  base + 9100,
		splitBypass:  base + 9150,
		markBase:     base + 10000,
		srcBase:      base + 11000,
		capture:      base + 12000,
	}
}

func compactBand(top int) ruleBand {
	return ruleBand{
		fwmarkBypass: top - 750,
		localBypass:  top - 700,
		splitBypass:  top - 650,
		markBase:     top - 600,
		srcBase:      top - 300,
		capture:      top,
	}
}

func bandHasPriority(b ruleBand, prio int) bool {
	return prio == b.fwmarkBypass ||
		prio == b.localBypass ||
		prio == b.splitBypass ||
		prio == b.capture ||
		(prio > b.markBase && prio <= b.markBase+255) ||
		(prio > b.srcBase && prio <= b.srcBase+255)
}

func bandAvailable(b ruleBand, rules []netlink.Rule) bool {
	if b.fwmarkBypass <= 0 || b.capture >= 32766 {
		return false
	}
	for _, r := range rules {
		if bandHasPriority(b, r.Priority) {
			return false
		}
	}
	return true
}

func slotsAvailable(base, count int, rules []netlink.Rule, routes []netlink.Route) bool {
	for _, r := range rules {
		for n := 0; n <= count; n++ {
			if r.Table == 21000+base+n {
				return false
			}
		}
		if r.Mask != nil && *r.Mask != 0 && !r.Invert {
			for n := 1; n <= count; n++ {
				if (uint32(0x4e530000+base+n)^r.Mark)&*r.Mask == 0 {
					return false
				}
			}
		}
	}
	for _, r := range routes {
		if r.Table >= 21000+base && r.Table <= 21000+base+count {
			return false
		}
	}
	return true
}

func prefixHalfMask(dst *net.IPNet) (family int, half uint8, isDefault bool) {
	if dst == nil {
		return 0, 0, true
	}
	ones, bits := dst.Mask.Size()
	if ones == 0 {
		return 0, 0, true
	}
	if ones != 1 {
		return 0, 0, false
	}
	if bits == 32 {
		ip4 := dst.IP.To4()
		if ip4 == nil {
			return 0, 0, false
		}
		if ip4[0]&0x80 == 0 {
			return unix.AF_INET, 1, false
		}
		return unix.AF_INET, 2, false
	}
	if bits == 128 {
		ip16 := dst.IP.To16()
		if ip16 == nil {
			return 0, 0, false
		}
		if ip16[0]&0x80 == 0 {
			return unix.AF_INET6, 1, false
		}
		return unix.AF_INET6, 2, false
	}
	return 0, 0, false
}

// foreignDefaultTables returns routing table IDs (excluding local/main/default
// and the engine's own slot range) that contain a full /0 default route or both
// /1 split-default halves. Split-only tables such as Tailscale's 100.64.0.0/10
// table 52 are excluded so they remain above engine capture.
func foreignDefaultTables(slotBase int, routes []netlink.Route) map[int]bool {
	out := make(map[int]bool)
	halves4 := make(map[int]uint8)
	halves6 := make(map[int]uint8)
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		t := r.Table
		if t <= 0 || t == unix.RT_TABLE_LOCAL || t == unix.RT_TABLE_MAIN || t == unix.RT_TABLE_DEFAULT {
			continue
		}
		if t >= 21000+slotBase && t <= 21255+slotBase {
			continue
		}
		fam, half, isDef := prefixHalfMask(r.Dst)
		if isDef {
			out[t] = true
			continue
		}
		if fam == unix.AF_INET {
			halves4[t] |= half
			if halves4[t] == 3 {
				out[t] = true
			}
		} else if fam == unix.AF_INET6 {
			halves6[t] |= half
			if halves6[t] == 3 {
				out[t] = true
			}
		}
	}
	return out
}

func isFullTunnelRule(r netlink.Rule, defaultTables map[int]bool) bool {
	if r.Priority <= 0 {
		return false
	}
	if r.Src != nil || r.Dst != nil || r.OifName != "" {
		return false
	}
	if r.IifName != "" && r.IifName != "lo" {
		return false
	}
	if r.Mark != 0 && !r.Invert {
		return false
	}
	return defaultTables[r.Table]
}

func minFullTunnelPriority(rules []netlink.Rule, defaultTables map[int]bool) int {
	minPrio := 0
	for _, r := range rules {
		if !isFullTunnelRule(r, defaultTables) {
			continue
		}
		if minPrio == 0 || r.Priority < minPrio {
			minPrio = r.Priority
		}
	}
	return minPrio
}

// chooseBand selects a collision-free rule priority band strictly above (lower
// priority number than) any active foreign full-tunnel VPN rule. When no
// foreign full-tunnel VPN rule exists, it prefers standardBand(14000) so
// repeated VPN reconnects (ip rule add without pref -> lowest-1) never exhaust
// priority headroom over long uptimes.
func chooseBand(current ruleBand, rules []netlink.Rule, defaultTables map[int]bool) (ruleBand, bool) {
	minFT := minFullTunnelPriority(rules, defaultTables)
	if minFT == 0 {
		// Prefer standardBand(14000+) for headroom; fall back to 0..13000 if needed.
		for base := 14000; base+12000 < 32766; base += 1000 {
			cand := standardBand(base)
			if bandAvailable(cand, rules) {
				return cand, true
			}
		}
		for base := 0; base < 14000; base += 1000 {
			cand := standardBand(base)
			if bandAvailable(cand, rules) {
				return cand, true
			}
		}
		return ruleBand{}, false
	}

	maxCapture := minFT - 1
	if current.capture > 0 && current.capture <= maxCapture && bandAvailable(current, rules) {
		return current, true
	}
	for base := 14000; base >= 0; base -= 1000 {
		cand := standardBand(base)
		if cand.capture <= maxCapture && bandAvailable(cand, rules) {
			return cand, true
		}
	}
	startTop := (maxCapture / 100) * 100
	if startTop > maxCapture {
		startTop = maxCapture
	}
	for top := startTop; top >= 900; top -= 100 {
		cand := compactBand(top)
		if cand.capture <= maxCapture && bandAvailable(cand, rules) {
			return cand, true
		}
	}
	for top := maxCapture; top >= 760; top -= 10 {
		cand := compactBand(top)
		if bandAvailable(cand, rules) {
			return cand, true
		}
	}
	return ruleBand{}, false
}

// foreignMarkBypassRules emits positive fwmark -> main bypass rules at
// band.fwmarkBypass so outer encrypted packets emitted by kernel WireGuard or a
// local VPN daemon bypass TUN capture instead of looping back into netswitch0.
func foreignMarkBypassRules(band ruleBand, families []int, foreignRules []netlink.Rule) []netlink.Rule {
	type key struct {
		fam  int
		mark uint32
		mask uint32
	}
	seen := make(map[key]bool)
	var out []netlink.Rule
	famAllowed := make(map[int]bool, len(families))
	for _, f := range families {
		famAllowed[f] = true
	}
	for _, r := range foreignRules {
		if r.Mark == 0 {
			continue
		}
		mask := ^uint32(0)
		if r.Mask != nil && *r.Mask != 0 {
			mask = *r.Mask
		}
		// Never mirror the engine's own 0x4e53xxxx mark namespace.
		if (r.Mark & 0xffff0000) == 0x4e530000 {
			continue
		}
		needsBypass := false
		if r.Invert {
			// e.g. wg-quick: "not fwmark 0xca6c lookup 51820".
			needsBypass = true
		} else if r.Table == unix.RT_TABLE_MAIN && r.Priority > band.fwmarkBypass {
			// A VPN daemon's explicit "fwmark X lookup main" rule that now sits
			// numerically after our stepped-down capture band.
			needsBypass = true
		}
		if !needsBypass {
			continue
		}
		targetFams := families
		if r.Family == unix.AF_INET || r.Family == unix.AF_INET6 {
			if !famAllowed[r.Family] {
				continue
			}
			targetFams = []int{r.Family}
		}
		for _, fam := range targetFams {
			k := key{fam: fam, mark: r.Mark, mask: mask}
			if seen[k] {
				continue
			}
			seen[k] = true
			m := mask
			br := netlink.NewRule()
			br.Family = fam
			br.Priority = band.fwmarkBypass
			br.Table = unix.RT_TABLE_MAIN
			br.Mark = r.Mark
			br.Mask = &m
			br.Protocol = routeProtocol
			br.Type = 1
			out = append(out, *br)
		}
	}
	return out
}

func isTunnelLink(link netlink.Link, markedVPN bool) bool {
	if markedVPN {
		return true
	}
	if link == nil {
		return false
	}
	switch link.Type() {
	case "wireguard", "tun", "tuntap", "ipip", "sit", "gre":
		return true
	}
	attrs := link.Attrs()
	if attrs == nil {
		return false
	}
	return attrs.Flags&net.FlagPointToPoint != 0 || attrs.EncapType == "none"
}

func coveredByBypass(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(dst.IP)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	ones, _ := dst.Mask.Size()
	p := netip.PrefixFrom(addr, ones).Masked()
	for _, cidr := range bypass {
		bp := netip.MustParsePrefix(cidr)
		if bp.Addr().Is4() == p.Addr().Is4() && bp.Bits() <= p.Bits() && bp.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// splitTunnelBypassRules preserves non-default subnet routes installed in main
// on unconfigured tunnel links (for example corporate split-tunnel VPN routes
// outside RFC1918/CGNAT) by bypassing TUN capture at band.splitBypass.
func splitTunnelBypassRules(band ruleBand, links []netlink.Link, configured map[int]bool, tunIndex int, foreignRoutes []netlink.Route, ipv4Only bool) []netlink.Rule {
	unconfiguredTunnels := make(map[int]bool)
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		idx := link.Attrs().Index
		if idx <= 0 || idx == tunIndex || configured[idx] {
			continue
		}
		if isTunnelLink(link, false) {
			unconfiguredTunnels[idx] = true
		}
	}
	if len(unconfiguredTunnels) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []netlink.Rule
	for _, r := range foreignRoutes {
		if r.Table != unix.RT_TABLE_MAIN || r.Type != unix.RTN_UNICAST || !unconfiguredTunnels[r.LinkIndex] {
			continue
		}
		if ipv4Only && r.Family == unix.AF_INET6 {
			continue
		}
		if r.Dst == nil {
			continue
		}
		ones, _ := r.Dst.Mask.Size()
		if ones <= 1 || coveredByBypass(r.Dst) {
			continue
		}
		fam := unix.AF_INET
		if r.Dst.IP.To4() == nil {
			fam = unix.AF_INET6
		}
		key := fmt.Sprintf("%d:%s", fam, r.Dst.String())
		if seen[key] {
			continue
		}
		seen[key] = true
		br := netlink.NewRule()
		br.Family = fam
		br.Priority = band.splitBypass
		br.Table = unix.RT_TABLE_MAIN
		br.Dst = prefix(r.Dst.String())
		br.Protocol = routeProtocol
		br.Type = 1
		out = append(out, *br)
	}
	return out
}

func hasAddrFamily(addrs []netip.Addr, v6 bool) bool {
	for _, a := range addrs {
		if a.Is6() == v6 {
			return true
		}
	}
	return false
}
