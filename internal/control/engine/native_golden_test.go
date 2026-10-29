package engine

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// Native goldens for the exact inputs of the frozen sing-box rule-file
// fixtures (test/fixtures/windows-golden.json, which stays untouched). Every
// expected configuration, identity and decision below is written out by hand;
// nothing is derived from the compiler or selector under test. The mapping
// from each old fixture family to these cases is docs/m4-native-goldens.md.

// The three Windows pins of the old fixtures and the engine identities they
// must compile to. The Windows engine keys owners by the same normalised,
// lower-cased path, so a pin matches every version of the same program.
const (
	browserPin = `C:\Apps\app-1.2.3\Browser.exe`
	gamePin    = `C:\Games\game.exe`
	storePin   = `C:\Program Files\WindowsApps\Example_1.2.3_x64__publisher\App.exe`
	browserID  = `c:\apps\app-*\browser.exe`
	gameID     = `c:\games\game.exe`
	storeID    = `c:\program files\windowsapps\example_*_x64__publisher\app.exe`
	toolID     = `c:\tools\tool.exe` // a known owner nobody pinned
)

var goldenLines = []lines.Line{{ID: "aa", Alias: "Ethernet"}, {ID: "bb", Alias: "Wi-Fi"}, {ID: "cc", Alias: "Phone"}}
var goldenPins = apps.Pins{{Path: browserPin, LineID: "aa"}, {Path: gamePin, LineID: "bb"}, {Path: storePin, LineID: "cc"}}
var goldenShares = []lines.Shares{
	{{ID: "aa", Value: 1}},
	{{ID: "aa", Value: .6}, {ID: "bb", Value: .4}},
	{{ID: "aa", Value: .5}, {ID: "bb", Value: .3}, {ID: "cc", Value: .2}},
}
var nativeLines = []platform.Line{{ID: "aa", Interface: "Ethernet"}, {ID: "bb", Interface: "Wi-Fi"}, {ID: "cc", Interface: "Phone"}}

// legacyPolicy is the exact input of the old "<count>-lines-pinned/combined"
// fixtures: all three pins, that count's shares, and the last line blocked.
// The unblocked companions leave the blocked set empty.
func legacyPolicy(count int, combine, blockLast bool) Policy {
	p := Policy{Lines: goldenLines[:count], AppLines: goldenPins, Combine: combine, Shares: goldenShares[count-1]}
	if blockLast {
		p.Blocked = []string{goldenLines[count-1].ID}
	}
	return p
}

// compileGolden checks the whole native revision against a literal
// configuration, then compiles it the way the engine does.
func compileGolden(t *testing.T, p Policy, n uint64, want policy.Config) *policy.Policy {
	t.Helper()
	r, err := NativeRevision(Revision{Number: n, Policy: p}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Config, want) {
		t.Fatalf("native config\n got %+v\nwant %+v", r.Config, want)
	}
	if r.N != n || r.Hash != policy.Hash(want) {
		t.Fatalf("revision %d hash %s does not bind the literal config", r.N, r.Hash)
	}
	compiled, err := policy.Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// decide checks one decision against a literal: "aa" (lane and line aa),
// "bb>aa" (lane bb redirected to physical line aa), "blocked" or "ipv6".
func decide(t *testing.T, p *policy.Policy, n uint64, app string, port uint16, ipv6 bool, k uint64, want string) {
	t.Helper()
	d, err := p.Decide(platform.Owner{AppID: app}, port, ipv6, k)
	switch want {
	case "blocked":
		if !errors.Is(err, policy.ErrBlocked) {
			t.Fatalf("%q port %d k %d: got %+v %v, want blocked", app, port, k, d, err)
		}
	case "ipv6":
		if !errors.Is(err, policy.ErrIPv6) {
			t.Fatalf("%q port %d k %d: got %+v %v, want IPv6 rejection", app, port, k, d, err)
		}
	default:
		lane, line, redirected := strings.Cut(want, ">")
		if !redirected {
			line = lane
		}
		if err != nil || d.Lane != lane || d.Line != line || d.Revision != n {
			t.Fatalf("%q port %d k %d: got %+v %v, want lane %s line %s revision %d", app, port, k, d, err, lane, line, n)
		}
	}
}

// sequence checks the unknown owner's decisions for k = 1..10 at one port.
func sequence(t *testing.T, p *policy.Policy, n uint64, port uint16, want string) {
	t.Helper()
	for i, line := range strings.Fields(want) {
		decide(t, p, n, "", port, false, uint64(i+1), line)
	}
}

func TestLegacyRuleFamiliesCompileToLiteralNativePolicy(t *testing.T) {
	// Decisions are for the browser (pinned aa), game (pinned bb), store app
	// (pinned cc), an unpinned known owner and an unknown owner, at source port
	// 40000 with sequence position k = 1. The share pick for k = 1 falls at
	// 0.618 of the range (k × 0x9E3779B97F4A7C15 / 2^64).
	for _, tc := range []struct {
		name            string
		count           int
		combine, open   bool
		config          policy.Config
		decisions       [5]string
		sequence        string // unknown owner, k = 1..10, port 40000
		unknown, gameAt policy.Prediction
	}{
		// One line: the old fixtures blocked the only line, which the native
		// engine refuses (TestLegacyOneLineBlockedMainIsRejectedNatively).
		// These are the unblocked companions: the pins to bb and cc name no
		// line and drop out, and everything takes aa.
		{name: "1 line pinned", count: 1, open: true,
			config:    policy.Config{Lines: nativeLines[:1], AppLines: map[string]string{browserID: "aa"}, Shares: map[string]uint64{"aa": 1_000_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Line: "aa"}, gameAt: policy.Prediction{Line: "aa"}},
		{name: "1 line combined", count: 1, open: true, combine: true,
			config:    policy.Config{Lines: nativeLines[:1], AppLines: map[string]string{browserID: "aa"}, Combine: true, Shares: map[string]uint64{"aa": 1_000_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Distribution: map[string]float64{"aa": 1}}, gameAt: policy.Prediction{Distribution: map[string]float64{"aa": 1}}},
		// Two lines with bb blocked (the old 2-lines-pinned/combined): the
		// old share rule kept bb's ports; natively a blocked line has no share,
		// so every combined flow stays on aa.
		{name: "2 lines pinned, bb blocked", count: 2,
			config:    policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Shares: map[string]uint64{"aa": 600_000}, Lanes: map[string]string{}, Blocked: []string{"bb"}},
			decisions: [5]string{"aa", "blocked", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Line: "aa"}, gameAt: policy.Prediction{Line: "bb", Blocked: true}},
		{name: "2 lines combined, bb blocked", count: 2, combine: true,
			config:    policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{"aa": 600_000}, Lanes: map[string]string{}, Blocked: []string{"bb"}},
			decisions: [5]string{"aa", "blocked", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Distribution: map[string]float64{"aa": 1}}, gameAt: policy.Prediction{Line: "bb", Blocked: true}},
		// Unblocked two-line companions keep 60:40.
		{name: "2 lines pinned, open", count: 2, open: true,
			config:    policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Shares: map[string]uint64{"aa": 600_000, "bb": 400_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Line: "aa"}, gameAt: policy.Prediction{Line: "bb"}},
		{name: "2 lines combined, open", count: 2, open: true, combine: true,
			config:    policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{"aa": 600_000, "bb": 400_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "bb", "bb", "bb"}, sequence: "bb aa bb aa aa bb aa bb aa aa",
			unknown: policy.Prediction{Distribution: map[string]float64{"aa": .6, "bb": .4}}, gameAt: policy.Prediction{Line: "bb"}},
		// Three lines with cc blocked (the old 3-lines-pinned/combined): the
		// remaining shares stay aa:bb = 5:3, so aa takes [0, 0.625).
		{name: "3 lines pinned, cc blocked", count: 3,
			config:    policy.Config{Lines: nativeLines, AppLines: map[string]string{browserID: "aa", gameID: "bb", storeID: "cc"}, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000}, Lanes: map[string]string{}, Blocked: []string{"cc"}},
			decisions: [5]string{"aa", "bb", "blocked", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Line: "aa"}, gameAt: policy.Prediction{Line: "bb"}},
		{name: "3 lines combined, cc blocked", count: 3, combine: true,
			config:    policy.Config{Lines: nativeLines, AppLines: map[string]string{browserID: "aa", gameID: "bb", storeID: "cc"}, Combine: true, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000}, Lanes: map[string]string{}, Blocked: []string{"cc"}},
			decisions: [5]string{"aa", "bb", "blocked", "aa", "aa"}, sequence: "aa aa bb aa aa bb aa bb aa aa",
			unknown: policy.Prediction{Distribution: map[string]float64{"aa": .625, "bb": .375}}, gameAt: policy.Prediction{Line: "bb"}},
		// Unblocked three-line companions keep 50:30:20.
		{name: "3 lines pinned, open", count: 3, open: true,
			config:    policy.Config{Lines: nativeLines, AppLines: map[string]string{browserID: "aa", gameID: "bb", storeID: "cc"}, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "cc", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa",
			unknown: policy.Prediction{Line: "aa"}, gameAt: policy.Prediction{Line: "bb"}},
		{name: "3 lines combined, open", count: 3, open: true, combine: true,
			config:    policy.Config{Lines: nativeLines, AppLines: map[string]string{browserID: "aa", gameID: "bb", storeID: "cc"}, Combine: true, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "cc", "bb", "bb"}, sequence: "bb aa cc aa aa bb aa cc bb aa",
			unknown: policy.Prediction{Distribution: map[string]float64{"aa": .5, "bb": .3, "cc": .2}}, gameAt: policy.Prediction{Line: "bb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const n = 41
			p := compileGolden(t, legacyPolicy(tc.count, tc.combine, !tc.open), n, tc.config)
			for i, app := range []string{browserID, gameID, storeID, toolID, ""} {
				decide(t, p, n, app, 40000, false, 1, tc.decisions[i])
				// IPv6 is off in every old rule fixture: public IPv6 is
				// rejected for every owner, pinned or not, before any pin.
				decide(t, p, n, app, 40000, true, 1, "ipv6")
			}
			sequence(t, p, n, 40000, tc.sequence)
			// Source ports below 1024 stay on the main lane; 1024 itself is
			// shared. A pin beats the low-port rule, and so does a block.
			decide(t, p, n, "", 1023, false, 1, "aa")
			decide(t, p, n, "", 1024, false, 1, tc.decisions[4])
			decide(t, p, n, gameID, 80, false, 1, tc.decisions[1])
			if got := p.Predict(""); !reflect.DeepEqual(got, tc.unknown) {
				t.Fatalf("unknown prediction %+v, want %+v", got, tc.unknown)
			}
			if got := p.Predict(gameID); !reflect.DeepEqual(got, tc.gameAt) {
				t.Fatalf("game prediction %+v, want %+v", got, tc.gameAt)
			}
		})
	}
}

// The old 1-lines-pinned/combined fixtures block the only line. Control never
// produces that (TestLegacyGoldenInputsAsControlProducesThem): the native
// translation carries the raw input through unchanged, and the engine refuses
// it before anything is applied. Nothing is edited to make it pass.
func TestLegacyOneLineBlockedMainIsRejectedNatively(t *testing.T) {
	for _, combine := range []bool{false, true} {
		raw := legacyPolicy(1, combine, true)
		r, err := NativeRevision(Revision{Number: 41, Policy: raw}, apppath.Windows)
		if err != nil {
			t.Fatal(err)
		}
		want := policy.Config{Lines: nativeLines[:1], AppLines: map[string]string{browserID: "aa"}, Combine: combine, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{"aa"}}
		if !reflect.DeepEqual(r.Config, want) {
			t.Fatalf("raw translation\n got %+v\nwant %+v", r.Config, want)
		}
		if _, err := policy.Compile(r); err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("combine %t: blocked main line compiled: %v", combine, err)
		}
		table := flows.New(flows.Defaults(), nil)
		if _, err := table.Apply(r); err == nil {
			t.Fatal("engine applied a policy that blocks the main line")
		}
		if _, err := table.Predict(browserID); !errors.Is(err, flows.ErrStopped) {
			t.Fatal("a refused revision left policy behind", err)
		}
		// The refusal is the blocked main line alone: the same translation
		// without it is the valid one-line policy of the previous test.
		want.Blocked = []string{}
		if _, err := policy.Compile(policy.Revision{N: 41, Hash: policy.Hash(want), Config: want}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyWindowsPinIdentities(t *testing.T) {
	// Every pin goes to bb so that a wrong match is visible against aa.
	pins := apps.Pins{{Path: browserPin, LineID: "bb"}, {Path: gamePin, LineID: "bb"}, {Path: storePin, LineID: "bb"}, {Path: `C:\Tools\tool.exe`, LineID: "zz"}, {Path: "", LineID: "bb"}}
	p := compileGolden(t, Policy{Lines: goldenLines[:2], AppLines: pins}, 5,
		policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "bb", gameID: "bb", storeID: "bb"}, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{}})
	for _, tc := range []struct{ path, identity, line string }{
		// The pinned paths themselves, other versions and other casing.
		{browserPin, browserID, "bb"},
		{`C:\Apps\app-2.0.0\Browser.exe`, browserID, "bb"},
		{`c:\APPS\APP-1.2.3\browser.EXE`, browserID, "bb"},
		{gamePin, gameID, "bb"},
		{`C:\Games\GAME.exe`, gameID, "bb"},
		{storePin, storeID, "bb"},
		{`C:\Program Files\WindowsApps\Example_2.0.1.0_x64__publisher\App.exe`, storeID, "bb"},
		// Near neighbours are different programs and stay on the main line.
		{`C:\Apps\app-1.2.3-beta\Browser.exe`, `c:\apps\app-1.2.3-beta\browser.exe`, "aa"},
		{`C:\Apps\Browser.exe`, `c:\apps\browser.exe`, "aa"},
		{`D:\Apps\app-1.2.3\Browser.exe`, `d:\apps\app-*\browser.exe`, "aa"},
		{`C:\Apps\app-1.2.3\Browser-helper.exe`, `c:\apps\app-*\browser-helper.exe`, "aa"},
		{`C:\Games\game2.exe`, `c:\games\game2.exe`, "aa"},
		{`C:\Games\Mods\game.exe`, `c:\games\mods\game.exe`, "aa"},
		{`C:\Program Files\WindowsApps\Example_1.2.3_arm64__publisher\App.exe`, `c:\program files\windowsapps\example_*_arm64__publisher\app.exe`, "aa"},
		{`C:\Program Files\WindowsApps\Example_1.2.3_x64__other\App.exe`, `c:\program files\windowsapps\example_*_x64__other\app.exe`, "aa"},
		{`C:\Program Files\WindowsApps\Example_1.2.3_x64__publisher\Helper.exe`, `c:\program files\windowsapps\example_*_x64__publisher\helper.exe`, "aa"},
		{`C:\Tools\tool.exe`, toolID, "aa"},
	} {
		// The Windows owner lookup reports this identity for a process at
		// that path; the decision joins pin and owner on the literal string.
		if got := apps.AppKey(tc.path); got != tc.identity {
			t.Fatalf("owner identity of %s is %q, want %q", tc.path, got, tc.identity)
		}
		decide(t, p, 5, tc.identity, 40000, false, 1, tc.line)
	}
	// Saved order decides between pins that name the same program at two
	// versions: the later entry wins, whichever version it carries.
	for _, tc := range []struct {
		pins apps.Pins
		line string
	}{
		{apps.Pins{{Path: browserPin, LineID: "aa"}, {Path: `C:\Apps\app-2.0.0\Browser.exe`, LineID: "bb"}}, "bb"},
		{apps.Pins{{Path: `C:\Apps\app-2.0.0\Browser.exe`, LineID: "bb"}, {Path: browserPin, LineID: "aa"}}, "aa"},
	} {
		compileGolden(t, Policy{Lines: goldenLines[:2], AppLines: tc.pins}, 6,
			policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: tc.line}, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{}})
	}
}

func TestLegacyUnknownLinesAndInvalidRevisions(t *testing.T) {
	// Pins, shares, lanes and blocks that name a line Control does not have
	// drop out of the revision; the lines themselves bind by interface alias.
	p := Policy{Lines: goldenLines[:2], AppLines: apps.Pins{{Path: gamePin, LineID: "zz"}}, Combine: true,
		Shares: lines.Shares{{ID: "aa", Value: .6}, {ID: "zz", Value: .4}}, Blocked: []string{"zz"}, Lanes: map[string]string{"aa": "zz", "zz": "aa", "bb": "aa"}}
	compiled := compileGolden(t, p, 9, policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{}, Combine: true, Shares: map[string]uint64{"aa": 600_000}, Lanes: map[string]string{"bb": "aa"}, Blocked: []string{}})
	decide(t, compiled, 9, gameID, 40000, false, 1, "aa")
	if _, err := NativeRevision(Revision{Number: 0, Policy: legacyPolicy(2, false, false)}, apppath.Windows); err == nil {
		t.Fatal("revision 0 accepted")
	}
	unnamed := legacyPolicy(1, false, false)
	unnamed.Lines = []lines.Line{{ID: "aa"}}
	if _, err := NativeRevision(Revision{Number: 1, Policy: unnamed}, apppath.Windows); err == nil {
		t.Fatal("line without an interface alias accepted")
	}
}

// The old lane selectors defaulted each line to itself and could be pointed
// at another line's outbound. Natively a lane keeps its name in the decision
// and the physical line follows the redirection, shares included.
func TestLegacyLaneRedirection(t *testing.T) {
	p := legacyPolicy(2, true, false)
	p.Lanes = map[string]string{"bb": "aa"}
	compiled := compileGolden(t, p, 12, policy.Config{Lines: nativeLines[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{"aa": 600_000, "bb": 400_000}, Lanes: map[string]string{"bb": "aa"}, Blocked: []string{}})
	decide(t, compiled, 12, gameID, 40000, false, 1, "bb>aa")
	decide(t, compiled, 12, browserID, 40000, false, 1, "aa")
	sequence(t, compiled, 12, 40000, "bb>aa aa bb>aa aa aa bb>aa aa bb>aa aa aa")
	if got := compiled.Predict(gameID); !reflect.DeepEqual(got, policy.Prediction{Line: "aa"}) {
		t.Fatalf("redirected pin prediction %+v", got)
	}
	if got := compiled.Predict(""); !reflect.DeepEqual(got, policy.Prediction{Distribution: map[string]float64{"aa": 1}}) {
		t.Fatalf("redirected share prediction %+v", got)
	}
}

// The old TUN configs carried an "ip_version 6 reject" rule only while IPv6
// was off. Natively the same revision decides IPv6 flows exactly like IPv4
// once allowed, and rejects every one of them while not.
func TestLegacyIPv6Families(t *testing.T) {
	for count := 1; count <= 3; count++ {
		for _, allowed := range []bool{false, true} {
			p := legacyPolicy(count, true, false)
			p.IPv6 = allowed
			want := policy.Config{Lines: nativeLines[:count], AppLines: map[string]string{browserID: "aa"}, Combine: true, Shares: map[string]uint64{"aa": 1_000_000}, Lanes: map[string]string{}, Blocked: []string{}, IPv6: allowed}
			v4 := [5]string{"aa", "aa", "aa", "aa", "aa"}
			switch count {
			case 2:
				want.AppLines[gameID], want.Shares = "bb", map[string]uint64{"aa": 600_000, "bb": 400_000}
				v4 = [5]string{"aa", "bb", "bb", "bb", "bb"}
			case 3:
				want.AppLines[gameID], want.AppLines[storeID], want.Shares = "bb", "cc", map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}
				v4 = [5]string{"aa", "bb", "cc", "bb", "bb"}
			}
			compiled := compileGolden(t, p, 3, want)
			for i, app := range []string{browserID, gameID, storeID, toolID, ""} {
				decide(t, compiled, 3, app, 40000, false, 1, v4[i])
				v6 := "ipv6"
				if allowed {
					v6 = v4[i]
				}
				decide(t, compiled, 3, app, 40000, true, 1, v6)
			}
		}
	}
}

// The old empty-apps fixture wrote a dummy "no-app-selected.exe" rule for every
// line. Natively empty apps compile to an empty pin set, and replacing a
// pinned revision with it leaves no pin behind: the pinned apps fall back to
// the main line under the new revision number.
func TestLegacyEmptyAppsReplacesPinsWithoutASentinel(t *testing.T) {
	empty := policy.Config{Lines: nativeLines, AppLines: map[string]string{}, Shares: map[string]uint64{}, Lanes: map[string]string{}, Blocked: []string{}}
	compileGolden(t, Policy{Lines: goldenLines}, 42, empty)
	pinned, err := NativeRevision(Revision{Number: 41, Policy: legacyPolicy(3, false, false)}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := NativeRevision(Revision{Number: 42, Policy: Policy{Lines: goldenLines}}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	table := flows.New(flows.Defaults(), nil)
	if _, err := table.Apply(pinned); err != nil {
		t.Fatal(err)
	}
	if got, _ := table.Predict(gameID); !reflect.DeepEqual(got, policy.Prediction{Line: "bb"}) {
		t.Fatalf("pinned prediction %+v", got)
	}
	applied, err := table.Apply(replacement)
	if err != nil || applied.N != 42 || applied.Hash != policy.Hash(empty) {
		t.Fatalf("replacement applied as %+v %v", applied, err)
	}
	for _, app := range []string{browserID, gameID, storeID, toolID, ""} {
		if got, _ := table.Predict(app); !reflect.DeepEqual(got, policy.Prediction{Line: "aa"}) {
			t.Fatalf("%q after replacement predicts %+v", app, got)
		}
	}
	ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Close()
	d, err := ticket.Resolve(platform.Owner{AppID: gameID, Path: gamePin})
	if err != nil || d.Lane != "aa" || d.Line != "aa" || d.Revision != 42 {
		t.Fatalf("formerly pinned game decided %+v %v", d, err)
	}
	// The failed adapter readdir had no cleanup effect. Its native replacement
	// is this complete-revision contract, including the nonempty starting state
	// above, rather than an invented successful directory scan.
	mapping, err := replayledger.DefaultMapping()
	if err != nil {
		t.Fatal(err)
	}
	traces, err := replayledger.Load("../../..", mapping)
	if err != nil {
		t.Fatal(err)
	}
	report, err := replayledger.Build(mapping, traces)
	if err != nil {
		t.Fatal(err)
	}
	var rows []replayledger.Row
	for _, row := range report.Rows {
		if row.Assertion == "internal/control/engine/native_golden_test.go#"+t.Name() {
			entry := traces[row.Hash].Entries[row.Seq]
			var value struct {
				Operation, Code, Kind string
				OK                    bool
			}
			if err := json.Unmarshal(entry.Value, &value); err != nil {
				t.Fatal(err)
			}
			if entry.Kind == "file-completion" {
				if value.Operation != "readdir" || value.OK || value.Code != "ERR_INVALID_ARG_TYPE" {
					t.Fatal("unknown cleanup failure", value)
				}
			} else if entry.Kind != "completion" || value.Kind != "file-completion" || traces[row.Hash].Entries[row.Seq-1].Kind != "file-completion" {
				t.Fatal("unknown cleanup completion", entry)
			}
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		t.Fatal("cleanup replacement has no bound entries")
	}
	cursor := replayledger.NewCursor(rows)
	for _, row := range rows {
		if err := cursor.Consume(t, row.Hash, row.Seq, row.Disposition); err != nil {
			t.Fatal(err)
		}
	}
	if err := cursor.Receipt(t); err != nil {
		t.Fatal(err)
	}
}
