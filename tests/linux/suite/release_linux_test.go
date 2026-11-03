//go:build linux

package suite

import (
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

func TestReleaseCatalogueHasNoBlockersOrPendingGates(t *testing.T) {
	formerlyDeferred := map[string]bool{
		"overload.udp-sessions-per-app":      false,
		"overload.udp-sessions-total":        false,
		"overload.tcp-connection-storm":      false,
		"overload.tcp-handshakes-in-flight":  false,
		"overload.tcp-flows-total":           false,
		"overload.tcp-buffer-budget":         false,
		"overload.rejection-notices-per-app": false,
		"overload.rejection-notices-total":   false,
		"overload.timewait-cap":              false,
		"overload.udp-pending-bytes":         false,
		"overload.unknown-owner-limits":      false,
		"overload.tun-write-queue":           false,
		"overload.memory-at-limit":           false,
		"protocol.flows-pagination":          false,
		"capacity.mixed-caps":                false,
		"udp.fifty-destinations-one-session": false,
		"lookup.gate-terminal":               false,
		"lookup.gate-app-scope":              false,
	}
	cases := Cases(Config{})
	if len(cases) == 0 {
		t.Fatal("empty suite catalogue")
	}
	for _, c := range cases {
		if c.ReleaseBlocker != "" {
			t.Errorf("unexpected release blocker on %s: %s", c.ID, c.ReleaseBlocker)
		}
		if c.Label == harness.Pending {
			t.Errorf("unexpected pending gate %s: %s", c.ID, c.Waits)
		}
		if _, ok := formerlyDeferred[c.ID]; ok {
			formerlyDeferred[c.ID] = true
		}
	}
	for id, present := range formerlyDeferred {
		if !present {
			t.Errorf("mandatory attribution/lookup case missing from suite catalogue: %s", id)
		}
	}
	if err := harness.CheckRelease(cases); err != nil {
		t.Fatalf("release gate rejected qualified 1.0 catalogue: %v", err)
	}
}
