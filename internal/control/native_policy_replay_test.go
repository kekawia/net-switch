package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

func TestNativePolicyScenarioClock(t *testing.T) {
	m, err := replayledger.DefaultMapping()
	if err != nil {
		t.Fatal(err)
	}
	traces, err := replayledger.Load("../..", m)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, trace := range traces {
		if trace.Name != "capReset" && trace.Name != "midnightGap" {
			continue
		}
		seen++
		if trace.Scenario.Now == nil {
			t.Fatal("missing scenario origin")
		}
		loc, err := time.LoadLocation(trace.Scenario.Timezone)
		if err != nil {
			t.Fatal(err)
		}
		at := time.UnixMilli(*trace.Scenario.Now).In(loc)
		want := "2026-10-19T23:59:57Z"
		if trace.Name == "midnightGap" {
			want = "2026-09-05T23:59:59-04:00"
			if next := at.Add(time.Second).Format(time.RFC3339); next != "2026-09-06T01:00:00-03:00" {
				t.Fatal("Santiago missing midnight", next)
			}
		}
		if at.Format(time.RFC3339) != want {
			t.Fatal("scenario clock", at, want)
		}
	}
	if seen != 2 {
		t.Fatal("missing clock fixtures", seen)
	}
}

// Every transaction runs on the continuously started Core. Original file
// callbacks remain owned by the startup driver's exactly-once file cursor.
func replayNativeCombiningSuffix(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fileCursor *startupFileCursor) map[int]string {
	manual, strict := twoLineNativeConfig(map[string]string{}), twoLineNativeConfig(map[string]string{})
	manual.Combine = true
	manual.Shares = map[string]uint64{"a1": 250000, "b2": 750000}
	strict.Shares = map[string]uint64{}
	return replayNativePolicySteps(t, c, e, clock, files, trace, cmp, fileCursor, []nativePolicyStep{{129, 162, 152, manual}, {163, 194, 186, strict}, {195, 196, -1, strict}})
}

type nativePolicyStep struct {
	begin, end, settings int
	want                 policy.Config
}

func replayNativePolicySteps(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fileCursor *startupFileCursor, steps []nativePolicyStep) map[int]string {
	t.Helper()
	checked := map[int]string{}
	for _, step := range steps {
		effectStart := cmp.effectNext
		before := e.Snapshot()
		applies, logs, events := e.applies, len(files.logs), len(files.events)
		at, waits, probes := clock.Now(), clock.afterCalls.Load(), e.probes.Load()
		e.want = step.want
		e.check = nil
		if step.settings >= 0 {
			var write struct{ Text string }
			if err := json.Unmarshal(trace.Entries[step.settings].Value, &write); err != nil {
				t.Fatal(err)
			}
			wantSettings := replayJSON(t, []byte(write.Text))
			if reflect.DeepEqual(replayJSON(t, files.data[filepath.Join("/test", "settings.json")]), wantSettings) {
				t.Fatal("transaction precondition: settings already match")
			}
			e.check = func(r engine.Revision) error {
				for _, file := range []string{"settings.json", "settings.json.bak"} {
					if !reflect.DeepEqual(replayJSON(t, files.data[filepath.Join("/test", file)]), wantSettings) {
						return fmt.Errorf("%s not durable before apply", file)
					}
				}
				for _, file := range []string{"control-journal.json", "control-journal.json.bak"} {
					var j struct {
						Desired  engine.Revision
						Settings any
						Wanted   bool
					}
					if err := json.Unmarshal(files.data[filepath.Join("/test", file)], &j); err != nil {
						return err
					}
					if !j.Wanted || !reflect.DeepEqual(j.Desired, r) || !reflect.DeepEqual(j.Settings, wantSettings) {
						return fmt.Errorf("%s missing durable transaction", file)
					}
				}
				if e.Snapshot().AppliedRevision != before.AppliedRevision {
					return fmt.Errorf("publication before ack")
				}
				return nil
			}
		}
		var input struct {
			Method, Route string
			Body          json.RawMessage
			Headers       map[string]string
		}
		if err := json.Unmarshal(trace.Entries[step.begin].Value, &input); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(input.Method, "http://127.0.0.1:47821"+input.Route, bytes.NewReader(input.Body))
		r.Header.Set("X-Token", "native-replay")
		for k, v := range input.Headers {
			r.Header.Set(k, v)
		}
		actual := map[string]any{"method": r.Method, "route": r.URL.Path, "headers": input.Headers}
		if len(input.Body) > 0 {
			actual["body"] = replayJSON(t, input.Body)
		}
		if err := cmp.Observe(step.begin, "http", mustStartupJSON(t, actual)); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		(&HTTP{Core: c, Port: 47821, Token: "native-replay"}).ServeHTTP(response, r)
		files.recordOrder("api")
		if e.guardError != nil {
			t.Fatal("native transaction", e.guardError)
		}
		headers := map[string]string{}
		for k := range response.Header() {
			headers[k] = response.Header().Get(k)
		}
		if err := cmp.Observe(step.end, "api", mustStartupJSON(t, map[string]any{"status": response.Code, "headers": headers, "body": replayJSON(t, response.Body.Bytes())})); err != nil {
			t.Fatal(err)
		}
		order := []string{"api"}
		if step.settings >= 0 {
			order = []string{"write:control-journal.json", "write:control-journal.json.bak", "write:settings.json", "write:settings.json.bak", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "api"}
			if trace.Name == "lineOrder" || trace.Name == "lineRemove" {
				order = append(order[:len(order)-1], "log", "api")
			}
			if trace.Name == "lineAdd" {
				order = append(order[:len(order)-1], "lane-log", "lane-log", "log", "native:probe:a1", "native:probe-result:a1", "native:probe:000001", "native:probe-result:000001", "api")
			}
			if e.applies != applies+1 || e.Snapshot().AppliedPoint <= before.AppliedPoint {
				t.Fatal("missing ack before response")
			}
		} else if e.applies != applies {
			t.Fatal("read changed revision")
		}
		if err := cmp.Effects(order...); err != nil {
			t.Fatal(err)
		}
		var ruleFiles []string
		if step.settings >= 0 {
			ruleFiles = twoLineRevisionFiles()
		}
		ruleEntries := trace.Entries[step.begin+1 : step.end]
		if (trace.Name == "lineOrder" || trace.Name == "lineRemove") && step.settings >= 0 {
			// One live revision replaces both the old pre-save rule refresh and
			// the restart's complete compilation. The restart checker below
			// checks their positions relative to settings and other effects.
			last := 212
			if trace.Name == "lineRemove" {
				ruleFiles = append(ruleFiles, "apps-a1.json")
				last = 197
			} else {
				ruleFiles = append(ruleFiles, "apps-b2.json", "apps-a1.json", "share-a1.json", "cut-a1.json")
			}
			ruleEntries = append([]replayledger.Entry{}, trace.Entries[136:156]...)
			ruleEntries = append(ruleEntries, trace.Entries[192:last]...)
		}
		if trace.Name == "lineAdd" && step.settings >= 0 {
			ruleFiles = []string{"apps-a1.json", "apps-a1.json", "apps-000001.json", "share-000001.json", "cut-000001.json"}
			ruleEntries = append([]replayledger.Entry{}, trace.Entries[87:92]...)
			ruleEntries = append(ruleEntries, trace.Entries[128:148]...)
		}
		proof, err := fileCursor.CheckRevision(ruleEntries, ruleFiles, cmp, effectStart)
		if err != nil {
			t.Fatal("HTTP rule revision", err)
		}
		for seq, guard := range proof {
			checked[seq] = guard
		}
		wantLogs := logs
		if (trace.Name == "lineOrder" || trace.Name == "lineRemove") && step.settings >= 0 {
			wantLogs++
			note := "line order: Wi-Fi, Ethernet"
			if trace.Name == "lineRemove" {
				note = "removed Wi-Fi (Wi-Fi)"
			}
			if files.logs[logs] != note || e.Snapshot().Instance != before.Instance || !reflect.DeepEqual(e.calls[len(e.calls)-1:], []string{"apply"}) {
				t.Fatal("live line order changed session or diagnostic")
			}
		}
		if trace.Name == "lineAdd" && step.settings >= 0 {
			wantLogs += 3
			probes += 2
			if !reflect.DeepEqual(files.logs[logs:], []string{"Ethernet's apps now use Ethernet", "Wi-Fi's apps now use Wi-Fi", "added Wi-Fi (Wi-Fi)"}) {
				t.Fatal("live add diagnostics", files.logs[logs:])
			}
		}
		if clock.Now() != at || clock.afterCalls.Load() != waits || e.probes.Load() != probes || len(files.logs) != wantLogs || len(files.events) != events {
			t.Fatal("transaction timing or unexpected effects")
		}
		counts := map[string]int{}
		for n := uint64(1); n <= 400; n++ {
			d, err := e.active.Decide(platform.Owner{AppID: `c:\apps\unassigned.exe`}, 40000, false, n)
			if err != nil || d.Revision != e.Snapshot().AppliedRevision {
				t.Fatal("decision", d, err)
			}
			counts[d.Line]++
		}
		expectedCounts := map[string]int{"a1": 400}
		if trace.Name == "lineOrder" {
			expectedCounts = map[string]int{"b2": 400}
		}
		if step.want.Combine {
			expectedCounts = map[string]int{"a1": 100, "b2": 300}
			if step.want.Shares["a1"] == 500000 {
				// Multiplicative sequence has at most a one-flow imbalance here;
				// equal weights do not promise an exactly alternating sequence.
				if len(counts) != 2 || counts["a1"] < 199 || counts["a1"] > 201 || counts["b2"] < 199 || counts["b2"] > 201 {
					t.Fatal("equal-weight distribution", counts)
				}
				expectedCounts = counts
			}
		}
		if !reflect.DeepEqual(counts, expectedCounts) {
			t.Fatal("per-flow combining replacement", counts, expectedCounts)
		}
		checked[step.begin], checked[step.end] = "actual HTTP read and response", "actual HTTP read and response"
		for seq := step.begin + 1; seq < step.end; seq++ {
			entry := trace.Entries[seq]
			if entry.Kind == "timer-completion" {
				var timer struct{ MS int }
				_ = json.Unmarshal(entry.Value, &timer)
				if timer.MS != 300 || step.settings < 0 {
					t.Fatal("unexpected barrier")
				}
				checked[seq] = "acknowledged revision before response without timer"
			}
		}
	}
	return checked
}
