package control

import (
	"errors"
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

// These are behavioral goldens, not serialized engine configurations. Control
// computes lanes, caps and shares; the production compiler and selector must
// deliver the stated outcome. No installed engine or owner lookup is simulated
// by this test: health and exhaustion are explicit inputs at that boundary.
func TestNativePolicyDecisionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		up, exhausted, strict []string
		combine               bool
		lanes                 [3]string
		blocked               []string
		shares                lines.Shares
		// Pins to a1, b2, c3, unpinned known owner, unknown owner, in order.
		decisions [5]string
	}{
		{name: "home", up: []string{"a1", "b2", "c3"}, lanes: [3]string{"a1", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .5}, {ID: "b2", Value: .25}, {ID: "c3", Value: .25}}, decisions: [5]string{"a1", "b2", "c3", "a1", "a1"}},
		{name: "main down uses first open", up: []string{"b2", "c3"}, lanes: [3]string{"b2", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .5}, {ID: "b2", Value: .25}, {ID: "c3", Value: .25}}, decisions: [5]string{"b2", "b2", "c3", "b2", "b2"}},
		{name: "strict home still serves its pin", up: []string{"a1", "b2", "c3"}, strict: []string{"b2"}, lanes: [3]string{"a1", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .65}, {ID: "c3", Value: .35}}, decisions: [5]string{"a1", "b2", "c3", "a1", "a1"}},
		{name: "strict line is not a fallback", up: []string{"b2", "c3"}, strict: []string{"b2"}, lanes: [3]string{"c3", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .65}, {ID: "c3", Value: .35}}, decisions: [5]string{"c3", "b2", "c3", "c3", "c3"}},
		{name: "strict home down may fall back", up: []string{"a1", "c3"}, strict: []string{"b2"}, lanes: [3]string{"a1", "a1", "c3"}, shares: lines.Shares{{ID: "a1", Value: .65}, {ID: "c3", Value: .35}}, decisions: [5]string{"a1", "a1", "c3", "a1", "a1"}},
		{name: "cap moves secondary", up: []string{"a1", "b2", "c3"}, exhausted: []string{"b2"}, lanes: [3]string{"a1", "a1", "c3"}, shares: lines.Shares{{ID: "a1", Value: .65}, {ID: "c3", Value: .35}}, decisions: [5]string{"a1", "a1", "c3", "a1", "a1"}},
		{name: "cap moves main", up: []string{"a1", "b2", "c3"}, exhausted: []string{"a1"}, lanes: [3]string{"b2", "b2", "c3"}, shares: lines.Shares{{ID: "b2", Value: .5}, {ID: "c3", Value: .5}}, decisions: [5]string{"b2", "b2", "c3", "b2", "b2"}},
		{name: "all capped blocks secondary but exempts main", up: []string{"a1", "b2", "c3"}, exhausted: []string{"a1", "b2", "c3"}, lanes: [3]string{"a1", "b2", "c3"}, blocked: []string{"b2", "c3"}, decisions: [5]string{"a1", "blocked", "blocked", "a1", "a1"}},
		{name: "no open line while combining", up: []string{"a1", "b2", "c3"}, exhausted: []string{"a1"}, strict: []string{"b2", "c3"}, combine: true, lanes: [3]string{"a1", "b2", "c3"}, decisions: [5]string{"a1", "b2", "c3", "a1", "a1"}},
		{name: "all capped while combining", up: []string{"a1", "b2", "c3"}, exhausted: []string{"a1", "b2", "c3"}, combine: true, lanes: [3]string{"a1", "b2", "c3"}, blocked: []string{"b2", "c3"}, decisions: [5]string{"a1", "blocked", "blocked", "a1", "a1"}},
		{name: "all down returns home without inventing a cap", lanes: [3]string{"a1", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .5}, {ID: "b2", Value: .25}, {ID: "c3", Value: .25}}, decisions: [5]string{"a1", "b2", "c3", "a1", "a1"}},
		{name: "combining uses per flow selection", up: []string{"a1", "b2", "c3"}, combine: true, lanes: [3]string{"a1", "b2", "c3"}, shares: lines.Shares{{ID: "a1", Value: .5}, {ID: "b2", Value: .25}, {ID: "c3", Value: .25}}, decisions: [5]string{"a1", "b2", "c3", "b2", "b2"}},
		{name: "one open line uses main lane", up: []string{"a1", "b2", "c3"}, exhausted: []string{"a1", "b2"}, combine: true, lanes: [3]string{"c3", "c3", "c3"}, decisions: [5]string{"c3", "c3", "c3", "c3", "c3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := append(testLines(), lines.Line{ID: "c3", Alias: "Phone", Weight: 1})
			items[0].Weight = 2
			for i := range items {
				for _, id := range tc.strict {
					if items[i].ID == id {
						items[i].Strict = true
					}
				}
			}
			pins := apps.Pins{{Path: "/apps/main", LineID: "a1"}, {Path: "flatpak:org.example.Game", LineID: "b2"}, {Path: "snap:other", LineID: "c3"}}
			c, _, _, _ := testCore(t, map[string]any{"lines": items, "appLines": pins, "combine": tc.combine, "combineMode": "manual", "ipv6": "off"})
			for _, l := range c.lanes {
				l.health.Up = ptr(false)
			}
			for _, id := range tc.up {
				c.lanes[id].health.Up = ptr(true)
			}
			for _, id := range tc.exhausted {
				c.exhausted[id] = true
			}
			p := c.policyLocked()
			wantLanes := map[string]string{"a1": tc.lanes[0], "b2": tc.lanes[1], "c3": tc.lanes[2]}
			if !reflect.DeepEqual(p.Lanes, wantLanes) || !reflect.DeepEqual(p.Blocked, append([]string{}, tc.blocked...)) || !reflect.DeepEqual(p.Shares, append(lines.Shares{}, tc.shares...)) {
				t.Fatalf("policy lanes=%v blocked=%v shares=%v; want lanes=%v blocked=%v shares=%v", p.Lanes, p.Blocked, p.Shares, wantLanes, tc.blocked, tc.shares)
			}
			r, err := engine.NativeRevision(engine.Revision{Number: 7, Policy: p}, apppath.Linux)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := policy.Compile(r)
			if err != nil {
				t.Fatal(err)
			}
			for i, app := range []string{"/apps/main", "flatpak:org.example.Game", "snap:other", "/apps/unpinned", ""} {
				d, err := compiled.Decide(platform.Owner{AppID: app}, 40000, false, 1)
				if tc.decisions[i] == "blocked" {
					if !errors.Is(err, policy.ErrBlocked) {
						t.Fatalf("%q: expected blocked, got %+v %v", app, d, err)
					}
				} else if err != nil || d.Line != tc.decisions[i] || d.Revision != 7 {
					t.Fatalf("%q: got %+v %v; want physical line %s revision 7", app, d, err, tc.decisions[i])
				}
			}
			if _, err := compiled.Decide(platform.Owner{}, 40000, true, 1); !errors.Is(err, policy.ErrIPv6) {
				t.Fatal("disabled IPv6 admitted", err)
			}
			low, err := compiled.Decide(platform.Owner{}, 80, false, 1)
			if err != nil || low.Line != tc.lanes[0] {
				t.Fatal("low source port left the main lane", low, err)
			}
		})
	}
}
