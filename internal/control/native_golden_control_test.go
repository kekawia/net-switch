package control

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

// The old rule-file fixtures fed raw policies to the rule writer. This is the
// same input family as Control actually produces it: its policy assembly, the
// production native compiler with Windows identity rules, and the native
// selector, checked against literal configurations and decisions. The pure
// raw-input goldens are internal/control/engine/native_golden_test.go.
func TestLegacyGoldenInputsAsControlProducesThem(t *testing.T) {
	const (
		browserID = `c:\apps\app-*\browser.exe`
		gameID    = `c:\games\game.exe`
		storeID   = `c:\program files\windowsapps\example_*_x64__publisher\app.exe`
	)
	pins := apps.Pins{{Path: `C:\Apps\app-1.2.3\Browser.exe`, LineID: "aa"}, {Path: `C:\Games\game.exe`, LineID: "bb"}, {Path: `C:\Program Files\WindowsApps\Example_1.2.3_x64__publisher\App.exe`, LineID: "cc"}}
	native := []platform.Line{{ID: "aa", Interface: "Ethernet"}, {ID: "bb", Interface: "Wi-Fi"}, {ID: "cc", Interface: "Phone"}}
	allPins := map[string]string{browserID: "aa", gameID: "bb", storeID: "cc"}
	for _, tc := range []struct {
		name                    string
		count                   int
		weights                 [3]float64
		combine, ipv6, nopins   bool
		down, exhausted, strict []string
		config                  policy.Config
		// browser, game, store app, unpinned known owner, unknown owner; port 40000, k = 1.
		decisions [5]string
		sequence  string // unknown owner, k = 1..10
	}{
		// One line. Control never blocks the main line, whatever its state:
		// its lane target is itself and it is exempt from blocking.
		{name: "1 line, exhausted main stays open", count: 1, combine: true, exhausted: []string{"aa"},
			config:    policy.Config{Lines: native[:1], AppLines: map[string]string{browserID: "aa"}, Combine: true, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa"}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}},
		{name: "1 line, down and exhausted main stays open", count: 1, down: []string{"aa"}, exhausted: []string{"aa"},
			config:    policy.Config{Lines: native[:1], AppLines: map[string]string{browserID: "aa"}, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa"}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}},
		{name: "1 line, healthy", count: 1, combine: true,
			config:    policy.Config{Lines: native[:1], AppLines: map[string]string{browserID: "aa"}, Combine: true, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa"}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}},
		// Two lines, weights 3:2, sharing 60:40 as the old fixture did.
		{name: "2 lines pinned, healthy", count: 2, weights: [3]float64{3, 2},
			config:    policy.Config{Lines: native[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Shares: map[string]uint64{"aa": 600_000, "bb": 400_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "aa", "aa", "aa"}},
		{name: "2 lines combined, healthy", count: 2, weights: [3]float64{3, 2}, combine: true,
			config:    policy.Config{Lines: native[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{"aa": 600_000, "bb": 400_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "bb", "bb", "bb"}, sequence: "bb aa bb aa aa bb aa bb aa aa"},
		// An exhausted secondary with an open main is moved, not blocked, and
		// an exhausted line never shares; the raw fixture's "blocked bb" only
		// arises when nothing else is open.
		{name: "2 lines combined, bb exhausted moves to aa", count: 2, weights: [3]float64{3, 2}, combine: true, exhausted: []string{"bb"},
			config:    policy.Config{Lines: native[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa", "bb": "aa"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb>aa", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa"},
		{name: "2 lines combined, both exhausted blocks bb and exempts aa", count: 2, weights: [3]float64{3, 2}, combine: true, exhausted: []string{"aa", "bb"},
			config:    policy.Config{Lines: native[:2], AppLines: map[string]string{browserID: "aa", gameID: "bb"}, Combine: true, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa", "bb": "bb"}, Blocked: []string{"bb"}},
			decisions: [5]string{"aa", "blocked", "aa", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa"},
		// Three lines, weights 5:3:2, sharing 50:30:20 as the old fixture did.
		{name: "3 lines pinned, healthy", count: 3, weights: [3]float64{5, 3, 2},
			config:    policy.Config{Lines: native, AppLines: allPins, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "cc", "aa", "aa"}},
		{name: "3 lines combined, healthy", count: 3, weights: [3]float64{5, 3, 2}, combine: true,
			config:    policy.Config{Lines: native, AppLines: allPins, Combine: true, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "cc", "bb", "bb"}, sequence: "bb aa cc aa aa bb aa cc bb aa"},
		// Control re-weights the open lines over twenty slots (5:3 → 13:7),
		// unlike the raw fixture translation, which keeps aa:bb at 5:3.
		{name: "3 lines combined, cc exhausted moves to aa", count: 3, weights: [3]float64{5, 3, 2}, combine: true, exhausted: []string{"cc"},
			config:    policy.Config{Lines: native, AppLines: allPins, Combine: true, Shares: map[string]uint64{"aa": 650_000, "bb": 350_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "aa"}, Blocked: []string{}},
			decisions: [5]string{"aa", "bb", "cc>aa", "aa", "aa"}, sequence: "aa aa bb aa aa bb aa bb aa aa"},
		{name: "3 lines combined, only cc blocked", count: 3, weights: [3]float64{5, 3, 2}, combine: true, exhausted: []string{"aa", "cc"}, strict: []string{"bb"},
			config:    policy.Config{Lines: native, AppLines: allPins, Combine: true, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{"cc"}},
			decisions: [5]string{"aa", "bb", "blocked", "aa", "aa"}, sequence: "aa aa aa aa aa aa aa aa aa aa"},
		{name: "3 lines pinned, all exhausted blocks bb and cc", count: 3, weights: [3]float64{5, 3, 2}, exhausted: []string{"aa", "bb", "cc"},
			config:    policy.Config{Lines: native, AppLines: allPins, Shares: map[string]uint64{}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{"bb", "cc"}},
			decisions: [5]string{"aa", "blocked", "blocked", "aa", "aa"}},
		// Auto permits IPv6 only when every line has it.
		{name: "3 lines combined, IPv6 allowed", count: 3, weights: [3]float64{5, 3, 2}, combine: true, ipv6: true,
			config:    policy.Config{Lines: native, AppLines: allPins, Combine: true, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{}, IPv6: true},
			decisions: [5]string{"aa", "bb", "cc", "bb", "bb"}, sequence: "bb aa cc aa aa bb aa cc bb aa"},
		// Empty apps: no pins, no sentinel, everything on the main line even
		// though the weights still describe the lines.
		{name: "3 lines, empty apps", count: 3, weights: [3]float64{5, 3, 2}, nopins: true,
			config:    policy.Config{Lines: native, AppLines: map[string]string{}, Shares: map[string]uint64{"aa": 500_000, "bb": 300_000, "cc": 200_000}, Lanes: map[string]string{"aa": "aa", "bb": "bb", "cc": "cc"}, Blocked: []string{}},
			decisions: [5]string{"aa", "aa", "aa", "aa", "aa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []lines.Line{{ID: "aa", Alias: "Ethernet", Label: "Ethernet", Kind: ptr("wired")}, {ID: "bb", Alias: "Wi-Fi", Label: "Wi-Fi", Kind: ptr("wifi")}, {ID: "cc", Alias: "Phone", Label: "Phone", Kind: ptr("phone")}}[:tc.count]
			for i := range items {
				items[i].Weight = tc.weights[i]
				for _, id := range tc.strict {
					if items[i].ID == id {
						items[i].Strict = true
					}
				}
			}
			ipv6 := "off"
			if tc.ipv6 {
				ipv6 = "auto"
			}
			c, _, _, _ := testCore(t, map[string]any{"lines": items, "appLines": pins, "combine": tc.combine, "combineMode": "manual", "ipv6": ipv6})
			if tc.nopins {
				// Replacing the pins with none must leave nothing behind.
				if err := c.save(map[string]any{"appLines": apps.Pins{}}); err != nil {
					t.Fatal(err)
				}
			}
			for id, l := range c.lanes {
				l.health.Up = ptr(true)
				for _, down := range tc.down {
					if id == down {
						l.health.Up = ptr(false)
					}
				}
			}
			for _, id := range tc.exhausted {
				c.exhausted[id] = true
			}
			c.adapters = nil
			for _, l := range items {
				c.adapters = append(c.adapters, map[string]any{"alias": l.Alias, "ipv4s": []any{"192.0.2.1"}, "ipv6": tc.ipv6})
			}
			r, err := engine.NativeRevision(engine.Revision{Number: 41, Policy: c.policyLocked()}, apppath.Windows)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Config, tc.config) {
				t.Fatalf("native config\n got %+v\nwant %+v", r.Config, tc.config)
			}
			if r.N != 41 || r.Hash != policy.Hash(tc.config) {
				t.Fatalf("revision %d hash %s does not bind the literal config", r.N, r.Hash)
			}
			compiled, err := policy.Compile(r)
			if err != nil {
				t.Fatal(err)
			}
			check := func(app string, port uint16, v6 bool, k uint64, want string) {
				t.Helper()
				d, err := compiled.Decide(platform.Owner{AppID: app}, port, v6, k)
				switch want {
				case "blocked":
					if !errors.Is(err, policy.ErrBlocked) {
						t.Fatalf("%q k %d: got %+v %v, want blocked", app, k, d, err)
					}
				case "ipv6":
					if !errors.Is(err, policy.ErrIPv6) {
						t.Fatalf("%q k %d: got %+v %v, want IPv6 rejection", app, k, d, err)
					}
				default:
					lane, line, redirected := strings.Cut(want, ">")
					if !redirected {
						line = lane
					}
					if err != nil || d.Lane != lane || d.Line != line || d.Revision != 41 {
						t.Fatalf("%q port %d k %d: got %+v %v, want lane %s line %s revision 41", app, port, k, d, err, lane, line)
					}
				}
			}
			for i, app := range []string{browserID, gameID, storeID, `c:\tools\tool.exe`, ""} {
				check(app, 40000, false, 1, tc.decisions[i])
				v6 := "ipv6"
				if tc.ipv6 {
					v6 = tc.decisions[i]
				}
				check(app, 40000, true, 1, v6)
			}
			check("", 1023, false, 1, "aa")
			for i, line := range strings.Fields(tc.sequence) {
				check("", 40000, false, uint64(i+1), line)
			}
		})
	}
}
