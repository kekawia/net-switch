package observer

import (
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Each reading says when it was taken, on a clock shared by every process, so
// a restarted helper's readings compare with the previous helper's.
func TestMeterReadingsCarryWhenTheyWereTaken(t *testing.T) {
	first := readMeters()
	time.Sleep(20 * time.Millisecond)
	second := readMeters()
	if first.At <= 0 || second.At-first.At < 15 || second.At-first.At > 5000 {
		t.Fatalf("reading times %d then %d", first.At, second.At)
	}
}

func TestMibIfRow2MatchesTheWindowsLayout(t *testing.T) {
	// sizeof(MIB_IF_ROW2) on 64-bit Windows.
	if size := unsafe.Sizeof(windows.MibIfRow2{}); size != 1352 {
		t.Errorf("MIB_IF_ROW2 is %d bytes, want 1352", size)
	}
}
