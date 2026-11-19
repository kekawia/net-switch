package flows

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/kekawia/net-switch/internal/engine/policy"
)

func makeAutoTable(t *testing.T, now *time.Time, autoBalance bool, shares map[string]uint64) *Table {
	t.Helper()
	tbl := New(Defaults(), nil)
	tbl.now = func() time.Time { return *now }
	cfg := policy.Config{
		Lines: []platform.Line{
			{ID: "cable", Interface: "Ethernet"},
			{ID: "wifi", Interface: "Wi-Fi"},
		},
		AppLines:    map[string]string{"pinned": "wifi"},
		Combine:     true,
		AutoBalance: autoBalance,
		Shares:      shares,
		Lanes:       map[string]string{"cable": "cable", "wifi": "wifi"},
		Blocked:     []string{},
		IPv6:        false,
	}
	rev := policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}
	if _, err := tbl.Apply(rev); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	return tbl
}

func admitFlow(t *testing.T, tbl *Table, app string, port uint16) (*ticket, string) {
	t.Helper()
	tuple := platform.Tuple{
		Source:      netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), port),
		Destination: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 443),
	}
	tk, err := tbl.Begin("tcp", tuple)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	dec, err := tk.Resolve(platform.Owner{AppID: app})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	return tk.(*ticket), dec.Line
}

func TestAutoBalanceSpreadsEqualIdleBurst(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	counts := map[string]int{}
	for i := range 8 {
		tk, line := admitFlow(t, tbl, "steam", uint16(40000+i))
		counts[line]++
		tk.Established(netip.MustParseAddr("192.0.2.1"))
	}
	if counts["cable"] != 4 || counts["wifi"] != 4 {
		t.Fatalf("expected 4/4 split across equal idle lines, got %v", counts)
	}
}

func TestAutoBalancePrefersIdleLineWhenFastLineSaturated(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 900_000, "wifi": 100_000})

	// Seed cable as a 10 MB/s line and wifi as a 1 MB/s line, then saturate cable
	// with a long-running download while wifi stays completely idle.
	cableFlow, first := admitFlow(t, tbl, "steam", 41000)
	if first != "cable" {
		t.Fatalf("expected faster idle line cable first, got %s", first)
	}
	cableFlow.Established(netip.MustParseAddr("192.0.2.1"))

	// Push 10 MB/s on cable for 6 seconds so its effectiveCap reaches ~10 MB/s and util ~1.0,
	// while recent burst decays away.
	for range 6 {
		cableFlow.Add(0, 10<<20)
		now = now.Add(time.Second)
		tbl.mu.Lock()
		tbl.balancer.sampleLocked(tbl.policy.ShareTargets(), now)
		tbl.mu.Unlock()
	}

	// Next connection must pick idle wifi (free headroom) instead of piling onto 100%-full cable.
	_, next := admitFlow(t, tbl, "steam", 41001)
	if next != "wifi" {
		t.Fatalf("expected idle wifi when cable is saturated, got %s (stats=%+v)", next, tbl.AutoBalanceStats())
	}
}

func TestAutoBalanceSteersAwayFromChokedLineAndRecovers(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})

	// Pinned app uploads 103 KB/s on wifi while Steam shares cable + wifi.
	pinned, pLine := admitFlow(t, tbl, "pinned", 42000)
	if pLine != "wifi" {
		t.Fatalf("expected pinned app on wifi, got %s", pLine)
	}
	pinned.Established(netip.MustParseAddr("192.0.2.2"))

	// Open initial shared flows on both lines; cable delivers 500 KB/s, wifi is choked to 6 KB/s.
	var cableShared, wifiShared *ticket
	for i := range 2 {
		tk, line := admitFlow(t, tbl, "steam", uint16(42001+i))
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		if line == "cable" {
			cableShared = tk
		} else {
			wifiShared = tk
		}
	}
	if cableShared == nil || wifiShared == nil {
		t.Fatal("expected initial shared flows on both lines")
	}

	// Simulate 8 seconds of Steam opening chunks while wifi stays choked at 6 KB/s shared
	// (plus 103 KB/s pinned upload) and cable delivers 500 KB/s.
	port := uint16(42100)
	for range 8 {
		cableShared.Add(0, 500<<10)
		wifiShared.Add(0, 6<<10)
		pinned.Add(103<<10, 0)
		now = now.Add(time.Second)
		tk, _ := admitFlow(t, tbl, "steam", port)
		port++
		tk.Established(netip.MustParseAddr("192.0.2.1"))
	}

	// Now measure 20 new connections: the overwhelming majority should go to healthy cable.
	picked := map[string]int{}
	for range 20 {
		tk, line := admitFlow(t, tbl, "steam", port)
		port++
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		picked[line]++
	}
	if picked["cable"] < 15 {
		t.Fatalf("expected choked wifi to back off and route >=15/20 flows to cable, got %v (stats=%+v)", picked, tbl.AutoBalanceStats())
	}
	if picked["wifi"] == 0 {
		t.Fatalf("expected at least 1 probe flow on wifi to allow recovery, got %v", picked)
	}

	// Now wifi un-stalls and delivers 500 KB/s for 4 seconds: it must recover cleanly.
	for range 4 {
		cableShared.Add(0, 500<<10)
		wifiShared.Add(0, 500<<10)
		now = now.Add(time.Second)
		tbl.mu.Lock()
		tbl.balancer.sampleLocked(tbl.policy.ShareTargets(), now)
		tbl.mu.Unlock()
	}
	recovered := map[string]int{}
	for range 10 {
		tk, line := admitFlow(t, tbl, "steam", port)
		port++
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		recovered[line]++
	}
	if recovered["wifi"] < 3 || recovered["cable"] < 3 {
		t.Fatalf("expected recovered wifi to share load again, got %v (stats=%+v)", recovered, tbl.AutoBalanceStats())
	}
}

func TestAutoBalanceIgnoresOldIdleKeepAlives(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})

	// Open 15 pinned idle connections on wifi (like Chrome/Discord keep-alive tabs).
	for i := range 15 {
		tk, _ := admitFlow(t, tbl, "pinned", uint16(43000+i))
		tk.Established(netip.MustParseAddr("192.0.2.2"))
	}
	// Advance clock 30 seconds with 0 traffic.
	now = now.Add(30 * time.Second)

	// An 8-connection shared burst must still spread evenly across both lines.
	counts := map[string]int{}
	for i := range 8 {
		tk, line := admitFlow(t, tbl, "steam", uint16(43100+i))
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		counts[line]++
	}
	if counts["cable"] != 4 || counts["wifi"] != 4 {
		t.Fatalf("idle keep-alive sockets starved wifi: got %v", counts)
	}
}

func TestAutoBalanceSteersAroundDialFaults(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})

	tbl.LineError("wifi", errors.New("connect: network is unreachable"))
	tbl.LineError("wifi", errors.New("connect: network is unreachable"))

	counts := map[string]int{}
	for i := range 6 {
		tk, line := admitFlow(t, tbl, "steam", uint16(44000+i))
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		counts[line]++
	}
	if counts["cable"] < 5 {
		t.Fatalf("expected dial faults on wifi to steer new flows to cable, got %v", counts)
	}
}

func TestManualCombineKeepsDeterministicShares(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, false, map[string]uint64{"cable": 750_000, "wifi": 250_000})
	if tbl.AutoBalanceStats() != nil {
		t.Fatalf("manual mode should not activate autoBalance stats")
	}
	// Inject heavy traffic on cable; manual mode must ignore live load and follow fixed shares.
	tk0, _ := admitFlow(t, tbl, "steam", 45000)
	tk0.Established(netip.MustParseAddr("192.0.2.1"))
	tk0.Add(0, 50<<20)
	now = now.Add(time.Second)

	counts := map[string]int{}
	for i := range 40 {
		tk, line := admitFlow(t, tbl, "steam", uint16(45001+i))
		tk.Established(netip.MustParseAddr("192.0.2.1"))
		counts[line]++
	}
	if counts["cable"] < 28 || counts["cable"] > 32 {
		t.Fatalf("manual 75/25 shares drifted from deterministic split: %v", counts)
	}
}

func TestAutoBalanceLongSampleGapMeasuresTrueRate(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})

	tk, line := admitFlow(t, tbl, "steam", 46000)
	tk.Established(netip.MustParseAddr("192.0.2.1"))
	// Transfer 30 MiB continuously over 30 seconds without opening new flows -> 1 MiB/s true rate.
	tk.Add(0, 30<<20)
	now = now.Add(30 * time.Second)

	stats := tbl.AutoBalanceStats()
	got := stats[line].SharedRate
	want := uint64(1 << 20)
	if got < want-128<<10 || got > want+128<<10 {
		t.Fatalf("expected 30s gap rate near %d B/s, got %d B/s (stats=%+v)", want, got, stats)
	}
}

func TestAutoBalanceRetireReleasesHandshakeCount(t *testing.T) {
	now := time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})

	tk, line := admitFlow(t, tbl, "steam", 46100)
	if got := tbl.AutoBalanceStats()[line].Handshakes; got != 1 {
		t.Fatalf("expected 1 active handshake before retire, got %d", got)
	}
	tk.TimeWait()
	if got := tbl.AutoBalanceStats()[line].Handshakes; got != 0 {
		t.Fatalf("expected handshake count to clear on TimeWait/Retire, got %d", got)
	}
	tk.Close()
}
