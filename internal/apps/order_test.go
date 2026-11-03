package apps

import (
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
)

func TestConnectionOrderAndZeroRetention(t *testing.T) {
	tracker := NewTracker(0)
	connections := []Connection{{ID: "first", Chains: []string{"line-a1"}}, {ID: "second", Chains: []string{"line-123456"}}, {ID: "third", Chains: []string{"line-012345"}}}
	tracker.Ingest(connections, 1000)
	if got := tracker.ConnectionIDsOffLine("unknown", "other"); !reflect.DeepEqual(got, []string{"second", "first", "third"}) {
		t.Fatalf("connection order: %v", got)
	}
	tracker.Ingest(nil, 1001)
	if len(tracker.Snapshot(nil)) != 0 {
		t.Fatal("explicit zero retention kept an idle app")
	}
}

func TestLinuxTrackerAndPinDedupeRules(t *testing.T) {
	tracker := NewTrackerWithRules(apppath.Linux)
	one := Connection{ID: "f1", AppID: "flatpak:org.one.Game", Chains: []string{"line-a1"}, Start: "2026-10-19T12:00:00Z"}
	one.Metadata.ProcessPath = "/app/bin/game"
	two := Connection{ID: "f2", AppID: "flatpak:org.two.Game", Chains: []string{"line-b2"}, Start: "2026-10-19T12:00:00Z"}
	two.Metadata.ProcessPath = "/app/bin/game"
	upper := Connection{ID: "p1", AppID: "/opt/Game/Game", Chains: []string{"line-a1"}, Start: "2026-10-19T12:00:00Z"}
	upper.Metadata.ProcessPath = "/opt/Game/Game"
	lower := Connection{ID: "p2", AppID: "/opt/game/game", Chains: []string{"line-b2"}, Start: "2026-10-19T12:00:00Z"}
	lower.Metadata.ProcessPath = "/opt/game/game"
	tracker.Ingest([]Connection{one, two, upper, lower}, 1000)

	pins := Pins{
		{Path: "flatpak:org.one.Game", LineID: "b2"},
		{Path: "flatpak:org.idle.App", LineID: "a1"},
		{Path: "/opt/Game/Game", LineID: "b2"},
		{Path: "/opt/game/game", LineID: "a1"},
		{Path: "/opt/tool/1.0/tool", LineID: "a1"},
		{Path: "/opt/tool/2.0/tool", LineID: "b2"},
	}
	order, normalized := pins.NormalizedWith(apppath.Linux)
	if len(order) != 5 || normalized["/opt/tool/*/tool"].LineID != "b2" {
		t.Fatalf("Linux pin normalization: order=%v map=%+v", order, normalized)
	}
	if normalized["/opt/Game/Game"].LineID != "b2" || normalized["/opt/game/game"].LineID != "a1" {
		t.Fatalf("case-distinct Linux pins collapsed: %+v", normalized)
	}

	outside := NewOutsideTrackerWithRules(apppath.Linux)
	outside.Ingest([]OutsideSample{
		{ID: "192.0.2.1:50000>198.51.100.1:443|101|2026-10-19T11:59:00Z", Path: "/app/bin/game", AppID: "flatpak:org.two.Game", Line: "a1", BeforeRouting: true},
		{ID: "192.0.2.1:50001>198.51.100.1:443|102|2026-10-19T11:59:00Z", Path: "/app/bin/launcher", AppID: "flatpak:org.only.Outside", Line: "b2", BeforeRouting: true},
	}, 1000)

	rows := MergeRowsWith(tracker.Snapshot(pins), outside, pins, apppath.Linux)
	byKey := map[string]Row{}
	for _, r := range rows {
		byKey[r.Key] = r
	}
	if r := byKey["flatpak:org.one.Game"]; r.Identity != "flatpak:org.one.Game" || r.Path != "/app/bin/game" || r.Line == nil || *r.Line != "b2" || r.Outside != nil {
		t.Fatalf("flatpak one row: %+v", r)
	}
	if r := byKey["flatpak:org.two.Game"]; r.Identity != "flatpak:org.two.Game" || r.Path != "/app/bin/game" || r.Line != nil || r.Outside == nil || r.Outside.Connections != 1 {
		t.Fatalf("flatpak two row: %+v", r)
	}
	if r := byKey["flatpak:org.idle.App"]; r.Identity != "flatpak:org.idle.App" || r.Path != "flatpak:org.idle.App" || r.Line == nil || *r.Line != "a1" {
		t.Fatalf("idle sandbox pin row: %+v", r)
	}
	if r := byKey["flatpak:org.only.Outside"]; r.Identity != "flatpak:org.only.Outside" || r.Path != "/app/bin/launcher" || r.Outside == nil || r.Outside.Connections != 1 {
		t.Fatalf("outside-only sandbox row: %+v", r)
	}
	if byKey["/opt/Game/Game"].Line == nil || *byKey["/opt/Game/Game"].Line != "b2" || byKey["/opt/game/game"].Line == nil || *byKey["/opt/game/game"].Line != "a1" {
		t.Fatalf("case-distinct rows: upper=%+v lower=%+v", byKey["/opt/Game/Game"], byKey["/opt/game/game"])
	}
}
