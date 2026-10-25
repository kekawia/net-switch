package lifecycle_test

import (
	"net/netip"
	"testing"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/lines"
)

func TestControlPolicyWitness(t *testing.T) {
	makeWitness := func(n uint64, target string) controlPolicyWitness {
		r := ce.Revision{Number: n, Policy: ce.Policy{
			Lines: []lines.Line{{ID: "a1", Alias: "eth-a"}, {ID: "b2", Alias: "eth-b"}},
			Lanes: map[string]string{"a1": target, "b2": "b2"},
		}}
		if target == "" {
			delete(r.Policy.Lanes, "a1")
		}
		native, err := lifecycle.NativeRevision(r)
		if err != nil {
			t.Fatal(err)
		}
		return controlPolicyWitness{desired: r, instance: "same-engine", status: protocol.Status{State: "on", Instance: "same-engine", Applied: &policy.Applied{N: n, Hash: native.Hash, Point: n + 10}}}
	}
	for _, name := range []string{
		"captured-2-then-3-before-admission", "before-snapshot", "after-snapshot", "redirected-physical-line", "main-fallback",
		"unwitnessed-future", "unwitnessed-intermediate", "pre-action-flow", "pre-action-snapshot", "wrong-lane", "wrong-line", "wrong-hash", "wrong-instance", "wrong-journal-instance", "missing-point", "reused-point", "reversed-snapshots",
	} {
		t.Run(name, func(t *testing.T) {
			before, after := makeWitness(2, "a1"), makeWitness(3, "a1")
			flow := flows.Record{Revision: 3, Lane: "a1", Line: "a1", PhysicalSource: netip.MustParseAddr("192.0.2.2")}
			wantRevision, wantAlias, valid := uint64(3), "eth-a", false
			switch name {
			case "captured-2-then-3-before-admission":
				before = makeWitness(3, "a1")
				valid = true
			case "before-snapshot":
				flow.Revision, wantRevision, valid = 2, 2, true
			case "after-snapshot":
				valid = true
			case "redirected-physical-line":
				after = makeWitness(3, "b2")
				flow.Line, wantAlias, valid = "b2", "eth-b", true
			case "main-fallback":
				after = makeWitness(3, "")
				valid = true
			case "unwitnessed-future":
				flow.Revision = 4
			case "unwitnessed-intermediate":
				after = makeWitness(4, "a1")
			case "pre-action-flow":
				flow.Revision = 1
			case "pre-action-snapshot":
				before = makeWitness(1, "a1")
				flow.Revision = 1
			case "wrong-lane":
				flow.Lane = "b2"
			case "wrong-line":
				flow.Line = "b2"
			case "wrong-hash":
				after.status.Applied.Hash = "wrong"
			case "wrong-instance":
				after.status.Instance = "replacement"
			case "wrong-journal-instance":
				after.instance = "replacement"
			case "missing-point":
				after.status.Applied.Point = 0
			case "reused-point":
				after.status.Applied.Point = before.status.Applied.Point
			case "reversed-snapshots":
				before, after = after, before
			}
			w, alias, err := chooseControlPolicyWitness(before, after, flow, "same-engine", "a1", "eth-a", 2)
			if !valid {
				if err == nil {
					t.Fatal("invalid admission evidence accepted", w, alias)
				}
				return
			}
			if err != nil || w.desired.Number != wantRevision || alias != wantAlias {
				t.Fatal("exact admission witness rejected", w, alias, err)
			}
		})
	}
}
