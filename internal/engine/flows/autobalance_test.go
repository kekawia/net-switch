package flows

import (
	"errors"
	"fmt"
	"math/rand"
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
		AppLines:    map[string]string{"pinned": "wifi", "pinned-cable": "cable"},
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

// balanceSim drives a table with traffic the way real lines carry it: each
// line has a true speed, light flows move a fixed small rate, and bulk flows
// split what is left of their line equally.
type balanceSim struct {
	t     *testing.T
	tbl   *Table
	now   *time.Time
	port  uint16
	speed map[string]float64 // true speed per line, bytes per second
	live  []*simFlow
}

type simFlow struct {
	tk   *ticket
	line string
	down float64 // fixed download rate; 0 means bulk
	up   float64 // fixed upload rate
	end  time.Time
}

func newBalanceSim(t *testing.T) *balanceSim {
	t.Helper()
	return newBalanceSimShares(t, map[string]uint64{"cable": 500_000, "wifi": 500_000})
}

// newBalanceSimShares uses Control's shares, which come from each line's
// long-memory peak speed.
func newBalanceSimShares(t *testing.T, shares map[string]uint64) *balanceSim {
	t.Helper()
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	s := &balanceSim{t: t, now: &now, port: 10000, speed: map[string]float64{"cable": 1.2 * (1 << 20), "wifi": 1.2 * (1 << 20)}}
	s.tbl = makeAutoTable(t, s.now, true, shares)
	return s
}

func (s *balanceSim) open(app string, down, up float64, life time.Duration) *simFlow {
	s.t.Helper()
	tk, line := admitFlow(s.t, s.tbl, app, s.port)
	s.port++
	tk.Established(netip.MustParseAddr("192.0.2.1"))
	f := &simFlow{tk: tk, line: line, down: down, up: up, end: s.now.Add(life)}
	s.live = append(s.live, f)
	return f
}

func (s *balanceSim) bulk(app string) *simFlow { return s.open(app, 0, 0, time.Hour) }

// step moves traffic for 250 ms, closes flows that ended and samples.
func (s *balanceSim) step() {
	const dt = 0.25
	for line, speed := range s.speed {
		bulk, fixed := 0, 0.0
		for _, f := range s.live {
			if f.line == line {
				if f.down == 0 {
					bulk++
				} else {
					fixed += f.down
				}
			}
		}
		for _, f := range s.live {
			if f.line != line {
				continue
			}
			down := f.down
			if down == 0 {
				down = max(0, speed-fixed) / float64(bulk)
			}
			f.tk.Add(uint64(f.up*dt), uint64(down*dt))
		}
	}
	*s.now = s.now.Add(250 * time.Millisecond)
	kept := s.live[:0]
	for _, f := range s.live {
		if s.now.After(f.end) {
			f.tk.Close()
		} else {
			kept = append(kept, f)
		}
	}
	s.live = kept
	s.tbl.AutoBalanceStats()
}

func (s *balanceSim) run(d time.Duration, each func(i int)) {
	for i := range int(d / (250 * time.Millisecond)) {
		if each != nil {
			each(i)
		}
		s.step()
	}
}

func (s *balanceSim) burst(n int) map[string]int {
	got := map[string]int{}
	for range n {
		got[s.bulk("steam").line]++
	}
	return got
}

func (s *balanceSim) closeAll() {
	for _, f := range s.live {
		f.tk.Close()
	}
	s.live = nil
}

func other(line string) string {
	if line == "cable" {
		return "wifi"
	}
	return "cable"
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

	// Cable starts as the faster line; saturate it with a long download while
	// wifi stays idle.
	cableFlow, first := admitFlow(t, tbl, "steam", 41000)
	if first != "cable" {
		t.Fatalf("expected faster idle line cable first, got %s", first)
	}
	cableFlow.Established(netip.MustParseAddr("192.0.2.1"))
	for range 6 {
		cableFlow.Add(0, 10<<20)
		now = now.Add(time.Second)
		tbl.AutoBalanceStats()
	}

	// The next connection must use idle wifi instead of piling onto full cable.
	_, next := admitFlow(t, tbl, "steam", 41001)
	if next != "wifi" {
		t.Fatalf("expected idle wifi when cable is saturated, got %s (stats=%+v)", next, tbl.AutoBalanceStats())
	}
}

// The defect found on 2026-11-21: small app connections on one line while the
// other carries a big download made the balancer think the quiet line was
// slow, so Steam's next connections all went to the busy line.
func TestAutoBalanceLightTrafficNeverHidesALine(t *testing.T) {
	s := newBalanceSim(t)
	busy := s.bulk("browser").line
	light := other(busy)
	before := s.tbl.AutoBalanceStats()[light].Cap
	// 15 s of chat and AI apps opening one small connection a second.
	s.run(15*time.Second, func(i int) {
		if i%4 == 0 {
			s.open("discord", 4<<10, 1<<10, 5*time.Second)
		}
	})
	stats := s.tbl.AutoBalanceStats()
	if stats[light].Cap < before {
		t.Fatalf("light traffic lowered %s's estimate from %d to %d (stats=%+v)", light, before, stats[light].Cap, stats)
	}
	if got := s.burst(8); got[light] < 4 {
		t.Fatalf("Steam's 8 connections went %v; the line with free speed (%s) got %d, want at least 4 (stats=%+v)", got, light, got[light], stats)
	}

	// After a quiet minute the next download still spreads evenly.
	s.closeAll()
	s.run(time.Minute, nil)
	if got := s.burst(8); got["cable"] != 4 || got["wifi"] != 4 {
		t.Fatalf("after idle, Steam's 8 connections went %v, want 4/4 (stats=%+v)", got, s.tbl.AutoBalanceStats())
	}
}

func TestAutoBalanceLightTrafficKeepsEstimateForMinutes(t *testing.T) {
	s := newBalanceSim(t)
	busy := s.bulk("browser").line
	light := other(busy)
	before := s.tbl.AutoBalanceStats()[light].Cap
	s.run(5*time.Minute, func(i int) {
		if i%2 == 0 {
			s.open("claude", 2<<10, 1<<10, 3*time.Second)
		}
	})
	if after := s.tbl.AutoBalanceStats()[light].Cap; after < before {
		t.Fatalf("five minutes of light traffic lowered %s's estimate from %d to %d", light, before, after)
	}
}

// Random background traffic of every density must never leave the light line
// out of a new download.
func TestAutoBalanceRandomBackgroundNeverStarvesLightLine(t *testing.T) {
	for _, perSecond := range []float64{0.25, 0.5, 1, 2, 4} {
		for seed := int64(1); seed <= 40; seed++ {
			rng := rand.New(rand.NewSource(seed))
			s := newBalanceSim(t)
			busy := s.bulk("browser").line
			light := other(busy)
			s.run(15*time.Second, func(int) {
				if rng.Float64() < perSecond/4 {
					s.open("discord", float64(1+rng.Intn(16))*1024, 1<<10, time.Duration(1+rng.Intn(8))*time.Second)
				}
			})
			if got := s.burst(8); got[light] < 3 {
				t.Fatalf("background %.2f/s seed %d: Steam's 8 connections went %v, light line %s got %d (stats=%+v)", perSecond, seed, got, light, got[light], s.tbl.AutoBalanceStats())
			}
		}
	}
}

func TestAutoBalanceSplitsByProvenSpeed(t *testing.T) {
	s := newBalanceSimShares(t, map[string]uint64{"cable": 909_091, "wifi": 90_909})
	s.speed["cable"] = 10 << 20
	s.speed["wifi"] = 1 << 20
	// Prove both speeds with pinned downloads, then stop them.
	s.open("pinned-cable", 0, 0, 8*time.Second)
	s.open("pinned", 0, 0, 8*time.Second)
	s.run(10*time.Second, nil)
	counts := map[string]int{}
	for range 22 {
		f := s.bulk("steam")
		counts[f.line]++
	}
	if counts["cable"] < 16 || counts["wifi"] < 1 {
		t.Fatalf("10 MB/s cable and 1 MB/s wifi split 22 connections %v, want most on cable and some on wifi (stats=%+v)", counts, s.tbl.AutoBalanceStats())
	}
}

// setups records n connection setups on line, rotating over four servers.
func setups(tbl *Table, line string, took time.Duration, n int) {
	for i := range n {
		tbl.LineConnected(line, netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i%4)}), took)
	}
}

// The case #151's decay rule was written for (2026-11-19): a pinned app filled
// Wi-Fi's upload, so downloads on Wi-Fi crawled while the cable had room. A
// choked queue makes every new connection on Wi-Fi slow to set up.
func TestAutoBalanceSteersAwayFromCongestedLineAndRecovers(t *testing.T) {
	s := newBalanceSim(t)
	// Usual setup times to four servers on both lines.
	setups(s.tbl, "wifi", 30*time.Millisecond, 4)
	setups(s.tbl, "cable", 30*time.Millisecond, 4)
	upload := s.open("pinned", 6<<10, 103<<10, time.Hour)
	s.open("pinned-cable", 500<<10, 4<<10, time.Hour)
	s.run(8*time.Second, func(i int) {
		if i%4 == 0 {
			setups(s.tbl, "wifi", 600*time.Millisecond, 1)
			setups(s.tbl, "cable", 32*time.Millisecond, 1)
		}
	})
	stats := s.tbl.AutoBalanceStats()
	if !stats["wifi"].Congested || stats["cable"].Congested {
		t.Fatalf("want wifi congested and cable not (stats=%+v)", stats)
	}
	picked := map[string]int{}
	for range 20 {
		picked[s.bulk("steam").line]++
	}
	if picked["cable"] < 15 {
		t.Fatalf("congested wifi still got %d of 20 new connections (%v, stats=%+v)", picked["wifi"], picked, stats)
	}
	if cap := stats["wifi"].Cap; cap < stats["wifi"].Prior/2 {
		t.Fatalf("congestion pulled wifi's estimate %d below half its prior %d", cap, stats["wifi"].Prior)
	}

	// The upload ends and setups are fast again: wifi must get its share back.
	upload.tk.Close()
	s.closeAll()
	s.run(15*time.Second, func(i int) {
		if i%4 == 0 {
			setups(s.tbl, "wifi", 31*time.Millisecond, 1)
		}
	})
	if s.tbl.AutoBalanceStats()["wifi"].Congested {
		t.Fatalf("wifi still congested after setups recovered (stats=%+v)", s.tbl.AutoBalanceStats())
	}
	if got := s.burst(10); got["wifi"] < 3 || got["cable"] < 3 {
		t.Fatalf("after recovery 10 connections went %v (stats=%+v)", got, s.tbl.AutoBalanceStats())
	}
}

func TestAutoBalanceCongestionAgesOutWithoutNewSetups(t *testing.T) {
	s := newBalanceSim(t)
	setups(s.tbl, "wifi", 30*time.Millisecond, 4)
	setups(s.tbl, "wifi", 800*time.Millisecond, 4)
	if !s.tbl.AutoBalanceStats()["wifi"].Congested {
		t.Fatal("four slow setups should mark wifi congested")
	}
	s.run(11*time.Second, nil)
	if s.tbl.AutoBalanceStats()["wifi"].Congested {
		t.Fatal("congestion evidence older than ten seconds must not count")
	}
}

// A full but healthy line adds a few tens of milliseconds to every setup (the
// user's lines showed +35-45 ms when full). That is not a choked queue, and a
// full line is already seen by its traffic.
func TestAutoBalanceNormalFullLoadDelayIsNotCongestion(t *testing.T) {
	for _, c := range []struct {
		name        string
		usual, full time.Duration
	}{
		{"near server three times usual but only +40 ms", 20 * time.Millisecond, 60 * time.Millisecond},
		{"far server +40 ms", 150 * time.Millisecond, 190 * time.Millisecond},
		{"far server +60 ms is under twice usual", 300 * time.Millisecond, 360 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
			tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
			server := netip.MustParseAddr("203.0.113.1")
			tbl.LineConnected("wifi", server, c.usual)
			for range 7 {
				now = now.Add(time.Second)
				tbl.LineConnected("wifi", server, c.full)
			}
			if st := tbl.AutoBalanceStats()["wifi"]; st.Congested || st.SetupSamples < 3 {
				t.Fatalf("want 3+ samples and no congestion: %+v", st)
			}
		})
	}
}

func TestAutoBalanceOneSlowServerIsNotCongestion(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	setups(tbl, "wifi", 30*time.Millisecond, 4)
	// The first setup to a new server only sets its baseline, however slow.
	tbl.LineConnected("wifi", netip.MustParseAddr("198.51.100.9"), 3*time.Second)
	if st := tbl.AutoBalanceStats()["wifi"]; st.SetupSamples != 0 {
		t.Fatalf("first setups to a server must only set baselines: %+v", st)
	}
	for i := range 6 {
		now = now.Add(time.Second)
		took := 31 * time.Millisecond
		if i == 2 || i == 4 {
			took = 2 * time.Second // one server answering slowly now and then
		}
		setups(tbl, "wifi", took, 1)
	}
	if st := tbl.AutoBalanceStats()["wifi"]; st.Congested {
		t.Fatalf("two slow setups among six fast ones must not mark the line congested: %+v", st)
	}
}

func TestAutoBalanceCongestedEstimateRecoversToPrior(t *testing.T) {
	s := newBalanceSim(t)
	start := s.tbl.AutoBalanceStats()["wifi"].Cap
	setups(s.tbl, "wifi", 30*time.Millisecond, 4)
	s.open("pinned", 20<<10, 100<<10, 20*time.Second)
	s.run(20*time.Second, func(i int) {
		if i%4 == 0 {
			setups(s.tbl, "wifi", 700*time.Millisecond, 1)
		}
	})
	low := s.tbl.AutoBalanceStats()["wifi"]
	if !low.Congested || float64(low.Cap) > 0.6*float64(start) {
		t.Fatalf("20 s of a choked queue left wifi's estimate at %d of %d (stats=%+v)", low.Cap, start, low)
	}
	if low.Cap < low.Prior/2 {
		t.Fatalf("estimate %d fell below half the prior %d", low.Cap, low.Prior)
	}
	s.run(5*time.Minute, nil)
	high := s.tbl.AutoBalanceStats()["wifi"]
	if high.Congested || float64(high.Cap) < 0.9*float64(high.Prior) {
		t.Fatalf("after five quiet minutes wifi's estimate is %d of prior %d (was %d)", high.Cap, high.Prior, low.Cap)
	}
}

func TestAutoBalanceSetupBaselinesStayBounded(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	for i := range 2000 {
		now = now.Add(time.Millisecond)
		tbl.LineConnected("cable", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 20*time.Millisecond)
	}
	if n := len(tbl.balancer.lines["cable"].setup.baselines); n > balanceSetupBaselineLimit {
		t.Fatalf("%d destination baselines kept, limit %d", n, balanceSetupBaselineLimit)
	}
}

func TestAutoBalanceIgnoresSetupsWhenOff(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, false, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	setups(tbl, "wifi", 30*time.Millisecond, 4)
	setups(tbl, "wifi", time.Second, 8)
	if l := tbl.balancer.lines["wifi"]; l != nil && (l.setup.baselines != nil || l.setup.congested(now)) {
		t.Fatal("Manual mode must not collect setup evidence")
	}
	// Setups on a line that is not sharing are ignored too.
	auto := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	auto.LineConnected("vpn", netip.MustParseAddr("203.0.113.1"), time.Second)
	if _, ok := auto.balancer.lines["vpn"]; ok {
		t.Fatal("a line outside the shares must not get balancer state")
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
	// Heavy traffic on cable; manual mode must ignore live load and follow fixed shares.
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
	// 30 MiB over 30 seconds without new flows is 1 MiB/s.
	tk.Add(0, 30<<20)
	now = now.Add(30 * time.Second)

	stats := tbl.AutoBalanceStats()
	got := stats[line].Rate
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

func TestAutoBalanceStatsNameEveryField(t *testing.T) {
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	tbl := makeAutoTable(t, &now, true, map[string]uint64{"cable": 500_000, "wifi": 500_000})
	st := tbl.AutoBalanceStats()
	if len(st) != 2 || st["cable"].Cap == 0 || st["cable"].Prior == 0 || fmt.Sprint(st["wifi"].SetupRatio) != "1" {
		t.Fatalf("unexpected fresh stats: %+v", st)
	}
}
