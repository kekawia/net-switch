package lifecycle_test

import (
	"net"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The ownership comparison decodes the rule exactly as the engine journals it
// (linux.ObjectJSON of a netlink.Rule, whose addresses encode as text) and
// compares every selector and the action with the kernel's `ip -N rule show`
// line. The first version decoded the addresses as byte slices, so every
// source or destination rule failed to decode, and it skipped action, protocol
// and the mark's mask. No root needed: pure shapes.
func TestNativeRuleKeysMatchTheEnginesJournalShape(t *testing.T) {
	src := netlink.NewRule()
	src.Family, src.Priority, src.Table, src.Protocol, src.Type = unix.AF_INET, 11001, 22001, 186, unix.RTN_UNICAST
	_, srcNet, _ := net.ParseCIDR("192.168.1.2/32")
	src.Src = srcNet
	mark := netlink.NewRule()
	mark.Family, mark.Priority, mark.Table, mark.Protocol, mark.Type = unix.AF_INET6, 10001, 22001, 186, unix.RTN_UNICAST
	mark.Mark = 0x4e530001
	full := ^uint32(0)
	mark.Mask = &full
	bypass := netlink.NewRule()
	bypass.Family, bypass.Priority, bypass.Table, bypass.Protocol, bypass.Type = unix.AF_INET, 9100, unix.RT_TABLE_MAIN, 186, unix.RTN_UNICAST
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	bypass.Dst = dst
	lo := netlink.NewRule()
	lo.Family, lo.Priority, lo.Table, lo.Protocol, lo.Type, lo.IifName = unix.AF_INET, 12000, 21001, 186, unix.RTN_UNICAST, "lo"
	for _, c := range []struct {
		rule *netlink.Rule
		live string
	}{
		{src, "11001: from 192.168.1.2 lookup 22001 proto 186"},
		{mark, "10001: from all fwmark 0x4e530001 lookup 22001 proto 186"},
		{bypass, "9100: from all to 10.0.0.0/8 lookup 254 proto 186"},
		{lo, "12000: from all iif lo lookup 21001 proto 186"},
	} {
		family := unix.AF_INET
		if c.rule.Family == unix.AF_INET6 {
			family = unix.AF_INET6
		}
		journaled, err := nativeRuleKey(linux.ObjectJSON(*c.rule))
		if err != nil {
			t.Fatal(err)
		}
		live, err := liveRuleKey(family, c.live)
		if err != nil {
			t.Fatal(err)
		}
		if journaled != live {
			t.Fatalf("journaled rule and live rule differ:\n%s\n%s", journaled, live)
		}
	}
	// Differences the comparison must see: action, protocol and mark mask.
	for _, c := range []struct{ live, differs string }{
		{"11001: from 192.168.1.2 prohibit proto 186", "action"},
		{"11001: from 192.168.1.2 lookup 22001 proto 4", "protocol"},
		{"11001: from 192.168.1.2 fwmark 0x0/0xff lookup 22001 proto 186", "mark mask"},
	} {
		journaled, _ := nativeRuleKey(linux.ObjectJSON(*src))
		live, err := liveRuleKey(unix.AF_INET, c.live)
		if err != nil {
			t.Fatal(c.differs, err)
		}
		if journaled == live {
			t.Fatalf("a rule differing in %s compared equal: %s", c.differs, live)
		}
	}
	// Selectors outside the comparison are refused, not skipped.
	if _, err := liveRuleKey(unix.AF_INET, "11001: from all uidrange 1000-1000 lookup 22001 proto 186"); err == nil || !strings.Contains(err.Error(), "uidrange") {
		t.Fatal("unsupported live selector was not refused", err)
	}
	ports := netlink.NewRule()
	*ports = *src
	ports.Dport = netlink.NewRulePortRange(80, 80)
	if _, err := nativeRuleKey(linux.ObjectJSON(*ports)); err == nil || !strings.Contains(err.Error(), "not support") {
		t.Fatal("unsupported journaled selector was not refused", err)
	}
}
