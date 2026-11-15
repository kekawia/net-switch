//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMatchAndCleanLinuxVPNBlockerName(t *testing.T) {
	cases := []struct {
		parts []string
		want  string
	}{
		{[]string{"mullvad"}, "Mullvad VPN"},
		{[]string{"protonvpn_killswitch"}, "Proton VPN"},
		{[]string{"wg-quick-wg0"}, "WireGuard"},
		{[]string{"wg0"}, "WireGuard"},
		{[]string{"nordlynx"}, "NordVPN"},
		{[]string{"ivpn_firewall"}, "IVPN"},
		{[]string{"filter", "nat"}, "VPN firewall"},
		{[]string{"custom_killswitch"}, "custom_killswitch"},
	}
	for _, tc := range cases {
		if got := cleanLinuxVPNBlockerName(tc.parts...); got != tc.want {
			t.Fatalf("cleanLinuxVPNBlockerName(%v) = %q, want %q", tc.parts, got, tc.want)
		}
	}
}

func TestIsLinuxFirewallBlockErr(t *testing.T) {
	for _, blockedErr := range []error{
		unix.EPERM,
		fmt.Errorf("write udp: %w", unix.EPERM),
		unix.EACCES,
		unix.ECONNREFUSED,
		unix.EHOSTUNREACH,
		unix.ENETUNREACH,
	} {
		if !isLinuxFirewallBlockErr(blockedErr) {
			t.Fatalf("expected %v to be classified as firewall block", blockedErr)
		}
	}
	for _, nonBlockErr := range []error{
		nil,
		os.ErrDeadlineExceeded,
		context.DeadlineExceeded,
		context.Canceled,
		unix.EINVAL,
	} {
		if isLinuxFirewallBlockErr(nonBlockErr) {
			t.Fatalf("expected %v NOT to be classified as firewall block", nonBlockErr)
		}
	}
}

func TestParseNftTableMsg(t *testing.T) {
	buildMsg := func(name string, flags uint32) []byte {
		var out []byte
		out = append(out, unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0) // nfgenmsg
		nameBytes := append([]byte(name), 0)
		nameAttrLen := 4 + len(nameBytes)
		var hdr [4]byte
		binary.NativeEndian.PutUint16(hdr[0:2], uint16(nameAttrLen))
		binary.NativeEndian.PutUint16(hdr[2:4], nftTableAttrName)
		out = append(out, hdr[:]...)
		out = append(out, nameBytes...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		if flags != 0 {
			binary.NativeEndian.PutUint16(hdr[0:2], 8)
			binary.NativeEndian.PutUint16(hdr[2:4], nftTableAttrFlags)
			out = append(out, hdr[:]...)
			var fb [4]byte
			binary.BigEndian.PutUint32(fb[:], flags)
			out = append(out, fb[:]...)
		}
		return out
	}

	if name, ok := parseNftTableMsg(buildMsg("mullvad", 0)); !ok || name != "mullvad" {
		t.Fatalf("active table: got (%q, %v), want (\"mullvad\", true)", name, ok)
	}
	if name, ok := parseNftTableMsg(buildMsg("mullvad", nftTableFlagDormant)); ok {
		t.Fatalf("dormant table should be ignored, got %q", name)
	}
}

func TestLoopbackTimeoutDoesNotTriggerVPNFirewallStepAside(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer listener.Close()

	var p Platform
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)

	// 1. Real UDP write + silent listener read deadline on 127.0.0.1 must return blocked=false.
	blocked, err := probeLocalTUNAddr(context.Background(), lo.Index, [4]byte{127, 0, 0, 1}, port, key[:], vpnProbeChallengeTimeout)
	if err != nil {
		t.Fatalf("probeLocalTUNAddr: %v", err)
	}
	if blocked {
		t.Fatal("silent UDP read timeout falsely classified as VPN firewall block")
	}

	// 2. Unroutable 198.18.0.2 on lo (ENETUNREACH on Connect) must also not falsely step aside.
	fw, err := p.CheckVPNFirewall(context.Background(), lo.Index, port, key[:])
	if err != nil {
		t.Fatalf("CheckVPNFirewall: %v", err)
	}
	if fw != nil {
		t.Fatalf("missing route or timeout without Netfilter block must not trigger VPN firewall step-aside: %+v", fw)
	}
	if live := p.checkLiveVPNFirewall(context.Background()); live != nil {
		t.Fatalf("live check without Netfilter block must not trigger step-aside: %+v", live)
	}
}

func TestIsolatedNetnsNftablesKillSwitchStepAside(t *testing.T) {
	if os.Getenv("NETSWITCH_ISOLATED_NETNS") != "1" {
		t.Skip("requires NETSWITCH_ISOLATED_NETNS=1")
	}
	ctx := context.Background()
	runNft := func(script string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft failed (%v): %s\n%s", err, out, script)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("nft", "flush", "ruleset").Run()
	})

	_ = exec.CommandContext(ctx, "ip", "link", "set", "lo", "up").Run()
	dir, err := os.MkdirTemp("", "ns-vpnfw-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	p, err := New(ctx, dir)
	if err != nil {
		t.Fatalf("New platform: %v", err)
	}
	defer p.Close()

	tun, err := p.OpenTun(ctx)
	if err != nil {
		t.Fatalf("OpenTun: %v", err)
	}
	defer tun.Close()

	var key [32]byte
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	tunIdx := p.tunSpec.Index

	// 1. Without Netfilter kill switch, TUN egress succeeds (read timeout is NOT a firewall block).
	fw, err := p.CheckVPNFirewall(ctx, tunIdx, 54321, key[:])
	if err != nil {
		t.Fatalf("CheckVPNFirewall clean: %v", err)
	}
	if fw != nil {
		t.Fatalf("unexpected VPNFirewall without kill switch: %+v", fw)
	}

	// 2. Active Mullvad-style nftables output drop blocks TUN egress and names Mullvad VPN.
	runNft("table inet mullvad {\n chain output {\n  type filter hook output priority 0; policy accept;\n  oifname \"" + p.tunSpec.Name + "\" drop\n }\n}\n")
	fw, err = p.CheckVPNFirewall(ctx, tunIdx, 54321, key[:])
	if err != nil {
		t.Fatalf("CheckVPNFirewall mullvad drop: %v", err)
	}
	if fw == nil || !fw.Blocked || !fw.SteppedOut || fw.Blocker != "Mullvad VPN" {
		t.Fatalf("CheckVPNFirewall mullvad = %+v, want Blocked+SteppedOut Blocker=Mullvad VPN", fw)
	}
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", "mullvad").Run()

	// 3. Reset via clean CheckVPNFirewall, then install wg0 + generic filter reject live.
	if fw, err := p.CheckVPNFirewall(ctx, tunIdx, 54321, key[:]); err != nil || fw != nil {
		t.Fatalf("CheckVPNFirewall reset: fw=%+v err=%v", fw, err)
	}
	if out, err := exec.CommandContext(ctx, "ip", "link", "add", "wg0", "type", "wireguard").CombinedOutput(); err == nil {
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "wg0").Run() })
		_ = exec.CommandContext(ctx, "ip", "link", "set", "wg0", "up").Run()
		runNft("table ip filter {\n chain output {\n  type filter hook output priority 0; policy accept;\n  oifname != \"wg0\" ip daddr 198.18.0.2 reject\n }\n}\n")
		live := p.checkLiveVPNFirewall(ctx)
		if live == nil || !live.Blocked || !live.SteppedOut || live.Blocker != "WireGuard" {
			t.Fatalf("checkLiveVPNFirewall wg0 reject = %+v, want Blocked+SteppedOut Blocker=WireGuard", live)
		}
		if again := p.checkLiveVPNFirewall(ctx); again != nil {
			t.Fatalf("second checkLiveVPNFirewall after step-aside must return nil, got %+v", again)
		}
	} else {
		t.Logf("wireguard kernel module unavailable (%s); testing generic reject table", strings.TrimSpace(string(out)))
		runNft("table inet nordvpn_killswitch {\n chain output {\n  type filter hook output priority 0; policy accept;\n  ip daddr 198.18.0.2 reject\n }\n}\n")
		live := p.checkLiveVPNFirewall(ctx)
		if live == nil || !live.Blocked || !live.SteppedOut || live.Blocker != "NordVPN" {
			t.Fatalf("checkLiveVPNFirewall nordvpn reject = %+v, want Blocked+SteppedOut Blocker=NordVPN", live)
		}
	}
}
