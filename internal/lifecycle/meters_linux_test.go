package lifecycle

import (
	"testing"
	"time"
)

// Linux meter readings say when they were taken (CLOCK_MONOTONIC), like the
// Windows helper's, so Control divides by the time between readings.
func TestLinuxMeterReadingsCarryWhenTheyWereTaken(t *testing.T) {
	read := func() int64 {
		t.Helper()
		v, err := linuxCall("meters", nil)
		if err != nil {
			t.Fatal(err)
		}
		at, _ := v.(map[string]any)["at"].(int64)
		return at
	}
	first := read()
	time.Sleep(20 * time.Millisecond)
	second := read()
	if first <= 0 || second-first < 15 || second-first > 5000 {
		t.Fatalf("reading times %d then %d", first, second)
	}
}
