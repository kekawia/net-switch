//go:build windows

package winengine

import (
	"context"
	"net/netip"
	"testing"

	"github.com/kekawia/net-switch/internal/journal"
	"github.com/kekawia/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func TestClassifyKillSwitchFilter(t *testing.T) {
	foreignSub := mustGUID("{11111111-2222-3333-4444-555555555555}")
	ifCond := mustGUID("{22222222-3333-4444-5555-666666666666}")

	// 1. WireGuard catch-all hard block -> matched, "WireGuard".
	name, ok := classifyKillSwitchFilter(wfpFilterSummary{
		Layer:          wfpLayerALEConnectV4,
		SubLayer:       foreignSub,
		SubLayerWeight: 0xFFFF,
		SubLayerName:   "WireGuard filters",
		FilterName:     "Block all outbound (IPv4)",
		ActionType:     fwpActionBlock,
	})
	if !ok || name != "WireGuard" {
		t.Fatalf("expected WireGuard match, got ok=%v name=%q", ok, name)
	}

	// 2. Proton VPN hard block -> matched, "Proton VPN".
	name, ok = classifyKillSwitchFilter(wfpFilterSummary{
		Layer:        wfpLayerALEConnectV6,
		SubLayer:     foreignSub,
		SubLayerName: "ProtonVPN Permanent Sublayer",
		ActionType:   fwpActionBlock,
		Conditions:   []windows.GUID{ifCond},
	})
	if !ok || name != "Proton VPN" {
		t.Fatalf("expected Proton VPN match, got ok=%v name=%q", ok, name)
	}

	// 3. Per-app Windows Defender Firewall rule (ALE_APP_ID condition) -> NOT kill switch.
	if _, ok := classifyKillSwitchFilter(wfpFilterSummary{
		Layer:      wfpLayerALEConnectV4,
		SubLayer:   foreignSub,
		FilterName: "Block SomeApp.exe",
		ActionType: fwpActionBlock,
		Conditions: []windows.GUID{wfpCondALEAppID},
	}); ok {
		t.Fatal("per-app block rule misclassified as system VPN kill switch")
	}

	// 4. Built-in OS / AppContainer / unnamed conditional hard-block rules -> ignored.
	for _, tc := range []wfpFilterSummary{
		{
			Layer:        wfpLayerALEConnectV4,
			SubLayer:     foreignSub,
			SubLayerName: "@FirewallAPI.dll,-28752",
			FilterName:   "Microsoft Network Isolation",
			ActionType:   fwpActionBlock,
		},
		{
			Layer:        wfpLayerALEConnectV4,
			SubLayer:     foreignSub,
			SubLayerName: "AppContainer Loopback",
			ActionType:   fwpActionBlock,
			Conditions:   []windows.GUID{wfpCondALEPackageID},
		},
		{
			Layer:        wfpLayerALEConnectV4,
			SubLayer:     foreignSub,
			SubLayerName: "Some OS Sublayer",
			ActionType:   fwpActionBlock,
			Conditions:   []windows.GUID{ifCond},
		},
	} {
		if got, ok := classifyKillSwitchFilter(tc); ok {
			t.Fatalf("built-in/conditional non-VPN filter misclassified as %q", got)
		}
	}

	// 5. Disabled filter -> ignored.
	if _, ok := classifyKillSwitchFilter(wfpFilterSummary{
		Layer:        wfpLayerALEConnectV4,
		SubLayer:     foreignSub,
		SubLayerName: "Mullvad Firewall",
		ActionType:   fwpActionBlock,
		Flags:        fwpmFilterFlagDisabled,
	}); ok {
		t.Fatal("disabled WFP filter matched")
	}

	// 6. Soft CLEAR_ACTION_RIGHT generic Windows Firewall base block -> ignored.
	if _, ok := classifyKillSwitchFilter(wfpFilterSummary{
		Layer:          wfpLayerALEConnectV4,
		SubLayer:       foreignSub,
		SubLayerWeight: 0x0100,
		SubLayerName:   "@FirewallAPI.dll,-28752",
		ActionType:     fwpActionBlock,
		Flags:          fwpmFilterFlagClearRight,
	}); ok {
		t.Fatal("soft CLEAR_ACTION_RIGHT base firewall rule misclassified as kill switch")
	}

	// 7. Net Switch's own sublayer -> ignored.
	if _, ok := classifyKillSwitchFilter(wfpFilterSummary{
		Layer:      wfpLayerALEConnectV4,
		SubLayer:   wfpOwnedSubLayerGUID,
		ActionType: fwpActionBlock,
	}); ok {
		t.Fatal("owned Net Switch sublayer misclassified as foreign kill switch")
	}
}

func TestLoopbackTimeoutDoesNotTriggerVPNFirewallStepAside(t *testing.T) {
	// Loopback interface index 1 permits UDP connect/write without WSAEACCES and
	// has no echo responder on port 9, simulating a stalled Wintun read pump.
	var key [32]byte
	key[0] = 0x42
	r := &Routes{}
	fw, err := r.CheckVPNFirewall(context.Background(), 1, 9, key[:])
	if err != nil {
		t.Fatalf("CheckVPNFirewall returned error: %v", err)
	}
	if fw != nil {
		t.Fatalf("read timeout without WSAEACCES falsely triggered VPNFirewall: %+v", fw)
	}
	for range 3 {
		if live := r.checkLiveVPNFirewall(context.Background()); live != nil {
			t.Fatalf("live read timeout falsely triggered VPNFirewall: %+v", live)
		}
	}
}

func TestMarkDefaultLUIDsSplitAndSynthesizedRoutes(t *testing.T) {
	mkRow := func(luid uint64, cidr string, metric, proto uint32) windows.MibIpForwardRow2 {
		p := netip.MustParsePrefix(cidr)
		return windows.MibIpForwardRow2{
			InterfaceLuid:     luid,
			DestinationPrefix: windows.IpAddressPrefix{Prefix: sockaddr(p.Addr()), PrefixLength: uint8(p.Bits())},
			Metric:            metric,
			Protocol:          proto,
		}
	}

	rows := []windows.MibIpForwardRow2{
		// LUID 1: physical /0 default.
		mkRow(1, "0.0.0.0/0", 25, 3),
		// LUID 2: split-default /1 + /1 (OpenVPN / WireGuard non-killswitch).
		mkRow(2, "0.0.0.0/1", 5, 3),
		mkRow(2, "128.0.0.0/1", 5, 3),
		mkRow(2, "::/1", 5, 3),
		mkRow(2, "8000::/1", 5, 3),
		// LUID 3: only one half of /1 -> NOT a full default route.
		mkRow(3, "0.0.0.0/1", 5, 3),
		// LUID 4: Net Switch's own metric-4096 Table=off synthesized route -> ignored as native default.
		mkRow(4, "0.0.0.0/0", 4096, 3),
	}

	d4, d6 := markDefaultLUIDs(rows)
	if !d4[1] {
		t.Fatal("LUID 1 /0 not marked default4")
	}
	if !d4[2] || !d6[2] {
		t.Fatalf("LUID 2 /1+/1 not marked default: d4=%v d6=%v", d4[2], d6[2])
	}
	if d4[3] {
		t.Fatal("single /1 half LUID 3 marked default4")
	}
	if d4[4] {
		t.Fatal("synthesized metric-4096 route marked as native default4")
	}
}

func TestVPNRouteFingerprintValidation(t *testing.T) {
	v := object{all: &objects{}, kind: "vpn-route"}
	good := journal.Fingerprint{
		"guid":     "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
		"luid":     "12345",
		"index":    "19",
		"prefix":   "0.0.0.0/0",
		"nextHop":  "0.0.0.0",
		"metric":   "4096",
		"protocol": "3",
	}
	if err := v.Validate(good); err != nil {
		t.Fatalf("expected valid vpn-route fingerprint, got: %v", err)
	}

	badWintun := journal.Fingerprint{
		"guid": wintun.DefaultGUID, "luid": "12345", "index": "19",
		"prefix": "0.0.0.0/0", "nextHop": "0.0.0.0", "metric": "4096", "protocol": "3",
	}
	if err := v.Validate(badWintun); err == nil {
		t.Fatal("accepted wintun.DefaultGUID for vpn-route")
	}

	badMetric := journal.Fingerprint{
		"guid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "luid": "12345", "index": "19",
		"prefix": "0.0.0.0/0", "nextHop": "0.0.0.0", "metric": "0", "protocol": "3",
	}
	if err := v.Validate(badMetric); err == nil {
		t.Fatal("accepted metric 0 for vpn-route")
	}
}
