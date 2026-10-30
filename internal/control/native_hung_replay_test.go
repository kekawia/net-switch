package control

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// SYSTEM-DESIGN 2-3 and NATIVE-REPLAY-RETIREMENT explicitly replace the old
// poll-count restart with observation failure/recovery. The caller has checked
// the identical instance, complete policy, revision, failure budget and calls
// at every poll, including the twentieth. There is deliberately no new ack.
func checkNativeHungRestartReplacement(t *testing.T, trace replayledger.Trace, clock *fakeClock, fc *startupFileCursor, checked map[int]string) {
	t.Helper()
	// The retired compilation is byte-for-byte the already checked startup
	// compilation. Compare every field and operation in order, with only the
	// four independently enumerated temporary publication identities changed.
	for i, old := range trace.Entries[66:86] {
		x := trace.Entries[395+i]
		if old.Kind == "completion" {
			continue
		}
		b, err := rewriteTraceStrings(old.Value, func(s string) string {
			for n := 5; n <= 8; n++ {
				s = strings.ReplaceAll(s, fmt.Sprintf(".oracle-%d.tmp", n), fmt.Sprintf(".oracle-%d.tmp", n+5))
			}
			return s
		})
		if err != nil || x.Kind != old.Kind || x.Direction != old.Direction || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, b)) {
			t.Fatal("retained compilation differs", x.Seq, err)
		}
		checked[x.Seq] = "retained complete policy replaces repeated compilation"
	}
	part := trace
	part.Entries = trace.Entries[:464]
	checkNativeLiveEntries(t, part, clock, fc, 368, 419, 425, twoLineNativeConfig(map[string]string{}), checked, nativeLiveRestartPlan(t, clock, "hungEngine", "the routing engine hasn't answered for 20 polls; restarting it"))
}
