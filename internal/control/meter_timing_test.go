package control

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kekawia/net-switch/internal/usage"
)

func timedMeters(rx int, at int64) []byte {
	return []byte(fmt.Sprintf(`{"adapters":[{"alias":"Ethernet","rx":%d,"tx":0}],"at":%d}`, rx, at))
}

// 2026-11-23: a busy PC delayed meter readings and delivered them back to
// back, so one second of traffic was divided by the 0.2 s floor and the cable
// was stored at 31 MB/s while doing 1.2 MB/s.
func TestMeterRateUsesWhenReadingsWereTaken(t *testing.T) {
	c, _, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.HelperLine(timedMeters(0, 5000))
	clock.advance(200) // taken a second apart, arrived 0.2 s apart
	c.HelperLine(timedMeters(1_000_000, 6000))
	if got := c.meters["Ethernet"].rate.Down; got != 1_000_000 {
		t.Fatalf("rate %.0f B/s, want 1000000 from the one second between readings", got)
	}
	clock.advance(1000) // the same reading again: no new interval
	c.HelperLine(timedMeters(1_000_000, 6000))
	if got := c.meters["Ethernet"].rate.Down; got != 1_000_000 {
		t.Fatalf("a repeated reading changed the rate to %.0f", got)
	}
	// Readings without a time (0.3.x helpers, recorded traces) keep the
	// arrival interval and its 0.2 s floor.
	clock.advance(100)
	c.HelperLine([]byte(`{"adapters":[{"alias":"Ethernet","rx":2000000,"tx":0}]}`))
	if got := c.meters["Ethernet"].rate.Down; got != 5_000_000 {
		t.Fatalf("untimed rate %.0f B/s, want the legacy 5000000", got)
	}
}

func TestFirstTimedReadingForgetsArrivalTimedPeaksOnce(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.usage.Peaks["a1"], c.usage.Peaks["b2"] = 32388274, 5242090
	c.HelperLine([]byte(`{"adapters":[{"alias":"Ethernet","rx":0,"tx":0}]}`))
	if len(c.usage.Peaks) != 2 {
		t.Fatal("an untimed reading reset the peaks")
	}
	c.HelperLine(timedMeters(0, 5000))
	if len(c.usage.Peaks) != 0 || !c.usage.PeaksTimed {
		t.Fatalf("peaks kept: %v timed=%v", c.usage.Peaks, c.usage.PeaksTimed)
	}
	weights := c.usage.AutoWeights(c.itemsLocked())
	if weights["a1"] != weights["b2"] {
		t.Fatal("Auto shares not equal while the lines learn their speeds again", weights)
	}
	c.usage.Peaks["a1"] = 1_200_000
	c.HelperLine(timedMeters(0, 6000))
	if c.usage.Peaks["a1"] != 1_200_000 {
		t.Fatal("a later timed reading dropped timed peaks")
	}
	forgot := 0
	for _, line := range files.logs {
		if strings.Contains(line, "forgot the lines' top speeds") {
			forgot++
		}
	}
	if forgot != 1 {
		t.Fatalf("reset logged %d times", forgot)
	}
}

// The problem report shows what Auto combining weighs lines by, so a wrong
// top speed is visible without reading an admin-only file.
func TestCombineFactsShowSpeedsAndShares(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{"lines": testLines(), "combine": true, "combineMode": "auto"})
	c.adapters = []map[string]any{{"alias": "Ethernet", "ipv4s": []any{"192.0.2.1"}}, {"alias": "Wi-Fi", "ipv4s": []any{"192.0.2.2"}}}
	c.routes = []map[string]any{{"interfaceAddress": "192.0.2.1"}, {"interfaceAddress": "192.0.2.2"}}
	c.routesAt = c.now()
	c.usage.Peaks["a1"] = 31 << 20
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	facts := map[string]string{}
	for _, f := range c.CombineFacts() {
		facts[f[0]] = f[1]
	}
	if facts["Combine"] != "on, auto" || facts["Line top speeds"] != "Ethernet 31.00 MB/s, Wi-Fi not measured yet (readings timed by arrival, which can read high)" || !strings.Contains(facts["New Shared connections split"], "Ethernet ") {
		t.Fatalf("facts: %q", facts)
	}
	c.HelperLine(timedMeters(0, 5000))
	for _, f := range c.CombineFacts() {
		if f[0] == "Line top speeds" && f[1] != "Ethernet not measured yet, Wi-Fi not measured yet (timed readings)" {
			t.Fatalf("after the reset: %q", f[1])
		}
	}
}

func TestUsageMergeNeverMixesArrivalTimedPeaks(t *testing.T) {
	saved := func(peak float64, timed bool) usage.Saved {
		s := emptyUsageSaved()
		s.Peaks["a1"], s.PeaksTimed = peak, timed
		return s
	}
	if got := mergeUsage(saved(32388274, false), saved(1_200_000, true), nil); got.Peaks["a1"] != 1_200_000 || !got.PeaksTimed {
		t.Fatal("the old file brought back a dropped peak", got.Peaks)
	}
	if got := mergeUsage(saved(2_000_000, true), saved(9_000_000, false), nil); got.Peaks["a1"] != 2_000_000 || !got.PeaksTimed {
		t.Fatal("arrival-timed peaks replaced timed ones", got.Peaks)
	}
	if got := mergeUsage(saved(3_000_000, true), saved(1_000_000, true), nil); got.Peaks["a1"] != 3_000_000 {
		t.Fatal("timed peaks no longer merge by the higher one", got.Peaks)
	}
}
