package lines

import (
	"encoding/json"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestNormalizeVPNAndProxyLines(t *testing.T) {
	raw := []any{
		map[string]any{
			"id":    "000001",
			"alias": "Ethernet",
			"label": "Cable",
			"kind":  "wired",
		},
		map[string]any{
			"id":         "000002",
			"alias":      "Mullvad",
			"label":      "Mullvad WireGuard",
			"vpn":        true,
			"onlyChosen": false,
			"fallback":   false,
		},
		map[string]any{
			"id":    "000003",
			"label": "Local Clash",
			"proxy": map[string]any{
				"protocol":       "socks5",
				"server":         "127.0.0.1:7890",
				"carrier":        "local",
				"udp":            true,
				"ipv6":           true,
				"credentialsRef": "proxy-000003",
				"credentialsRev": float64(4),
			},
		},
		// Invalid proxy (self-carrier) is rejected.
		map[string]any{
			"id": "000004",
			"proxy": map[string]any{
				"protocol": "socks5",
				"server":   "127.0.0.1:1080",
				"carrier":  "000004",
			},
		},
	}

	got := NormalizeLines(raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 valid lines, got %d", len(got))
	}

	// Physical line JSON shape must stay identical to 0.3.x (no vpn/proxy keys).
	physJSON, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal physical line: %v", err)
	}
	var physMap map[string]any
	if err := json.Unmarshal(physJSON, &physMap); err != nil {
		t.Fatalf("unmarshal physical line: %v", err)
	}
	for _, forbidden := range []string{"vpn", "onlyChosen", "fallback", "proxy"} {
		if _, exists := physMap[forbidden]; exists {
			t.Fatalf("physical line unexpectedly serialized %q: %s", forbidden, physJSON)
		}
	}

	if !got[1].VPN || got[1].IsOnlyChosen() || got[1].AllowsFallback() {
		t.Fatalf("unexpected VPN flags: %+v", got[1])
	}
	if got[2].Proxy == nil || !got[2].IsOnlyChosen() || got[2].AllowsFallback() {
		t.Fatalf("unexpected proxy flags: %+v", got[2])
	}
	if got[2].Alias != "proxy:000003" || got[2].Proxy.CredentialsRev != 4 || !got[2].Proxy.UDP || !got[2].Proxy.IPv6 {
		t.Fatalf("unexpected proxy spec: %+v (%+v)", got[2], got[2].Proxy)
	}
}

func TestSharingAndFallbackInvariants(t *testing.T) {
	items := []Line{
		{ID: "vpn1", Alias: "wg0", Label: "Work VPN", VPN: true, OnlyChosen: boolPtr(false), Weight: 1},
		{ID: "phys1", Alias: "eth0", Label: "Cable", Weight: 1},
		{ID: "phys2", Alias: "wlan0", Label: "Wi-Fi", Weight: 1},
		{ID: "proxy1", Alias: "proxy:proxy1", Label: "Proxy", Proxy: &ProxySpec{Protocol: "socks5", Server: "127.0.0.1:1080", Carrier: "local"}, Weight: 1},
	}

	// SharingLines skips VPN and proxy lines while still treating phys1 as primary.
	shared := SharingLines(items, map[string]bool{})
	if len(shared) != 2 || shared[0].ID != "phys1" || shared[1].ID != "phys2" {
		t.Fatalf("SharingLines = %+v, want [phys1, phys2]", shared)
	}

	// Other lines never fall back onto VPN or proxy lines even if phys2 is down.
	up := map[string]bool{"vpn1": true, "phys1": false, "phys2": false, "proxy1": true}
	target := LaneTarget(items, "phys1", up, map[string]bool{})
	if target == nil || *target != "phys1" {
		t.Fatalf("phys1 unexpectedly fell back onto virtual line: %v", target)
	}

	// Block-by-default: down VPN or proxy stays on its own lane so policy marks it blocked.
	upPhys := map[string]bool{"vpn1": false, "phys1": true, "phys2": true, "proxy1": false}
	if got := LaneTarget(items, "vpn1", upPhys, map[string]bool{}); got == nil || *got != "vpn1" {
		t.Fatalf("down VPN without fallback redirected to %v, want vpn1", got)
	}
	if got := LaneTarget(items, "proxy1", upPhys, map[string]bool{}); got == nil || *got != "proxy1" {
		t.Fatalf("down proxy without fallback redirected to %v, want proxy1", got)
	}

	// Explicit opt-in fallback allows VPN/proxy to fall back to open physical line.
	items[0].Fallback = boolPtr(true)
	items[3].Fallback = boolPtr(true)
	if got := LaneTarget(items, "vpn1", upPhys, map[string]bool{}); got == nil || *got != "phys1" {
		t.Fatalf("down VPN with fallback=true got %v, want phys1", got)
	}
	if got := LaneTarget(items, "proxy1", upPhys, map[string]bool{}); got == nil || *got != "phys1" {
		t.Fatalf("down proxy with fallback=true got %v, want phys1", got)
	}
}
