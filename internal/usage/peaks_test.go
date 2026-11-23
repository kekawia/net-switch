package usage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTimePeaksMarkerRoundTripsAndStaysOutOfOldRecords(t *testing.T) {
	u := New(time.UTC)
	u.Load(map[string]any{"lines": map[string]any{}, "peaks": map[string]any{"a1": 32388274.0}})
	if !u.TimePeaks() || len(u.Peaks) != 0 || u.TimePeaks() {
		t.Fatal("arrival-timed peaks must be dropped exactly once")
	}
	b, err := json.Marshal(u.Saved)
	if err != nil || !strings.Contains(string(b), `"peaksTimed":true`) {
		t.Fatalf("marker not saved: %s %v", b, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	again := New(time.UTC)
	again.Load(raw)
	if !again.PeaksTimed || again.TimePeaks() {
		t.Fatal("a saved timed record was treated as arrival-timed")
	}
	// Records without timed readings, like 0.3.x and the replay traces, keep
	// their exact shape.
	b, _ = json.Marshal(New(time.UTC).Saved)
	if string(b) != `{"lines":{},"peaks":{}}` {
		t.Fatalf("untimed record shape changed: %s", b)
	}
}
