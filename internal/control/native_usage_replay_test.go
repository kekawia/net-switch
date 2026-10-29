package control

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// Physical samples are supplied to the production worker-input consumer.
// Each poll's observations are checked before the next external input runs.
func replayNativeUsageSuffix(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fileCursor *startupFileCursor, start int) map[int]string {
	t.Helper()
	checked := map[int]string{}
	origin := clock.Now()
	if len(c.meters) != 0 || len(c.exhausted) != 0 || len(files.events) != 0 {
		t.Fatal("usage starting state")
	}
	for _, line := range []string{"a1", "b2"} {
		if v := c.usage.Used(line); v == nil || v.Bytes != 0 {
			t.Fatal("usage must start empty", line, v)
		}
	}
	initialWrites := len(files.writes)
	generated := map[string]bool{}
	originalID := c.op.ID
	c.op.ID = func() string {
		id := originalID()
		if generated[id] {
			t.Fatal("repeated native ID", id)
		}
		generated[id] = true
		return id
	}
	ids, reverse := map[string]string{}, map[string]string{}
	polls, reads := 0, 0
	resetTrace := trace.Name == "capReset"
	var exhaustedPoint uint64
	closes := 0
	base := e.fakeEngine
	base.readConnections = func(context.Context) ([]engine.Connection, error) {
		reads++
		files.recordOrder("native:connections")
		return []engine.Connection{}, nil
	}
	e.closeCheck = func(r engine.CloseRequest) (engine.CloseResult, error) {
		if !resetTrace || polls != 3 || r.Line != "b2" || r.Instance != e.Snapshot().Instance || r.StartedBeforePoint != exhaustedPoint || r.ConnectionIDs != nil || r.OperationID == "" || !generated[r.OperationID] {
			return engine.CloseResult{}, fmt.Errorf("unfenced reset closure: %+v", r)
		}
		files.recordOrder("native:close")
		closes++
		return engine.CloseResult{}, nil
	}
	lastPoll := origin.UnixMilli()
	startupCheck := e.check
	e.check = func(r engine.Revision) error {
		if err := startupCheck(r); err != nil {
			return err
		}
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			var j struct{ Closures []closureIntent }
			if err := json.Unmarshal(files.data[filepath.Join("/test", name)], &j); err != nil {
				return err
			}
			if len(j.Closures) != 1 {
				return fmt.Errorf("%s missing cap intent", name)
			}
			i := j.Closures[0]
			wantRevision, wantPoint := r.Number, uint64(0)
			if polls == 3 {
				wantRevision, wantPoint = r.Number-1, exhaustedPoint
			}
			if i.ID == "" || !generated[i.ID] || i.Request.OperationID != i.ID || i.Request.Line != "b2" || i.Request.Instance != e.Snapshot().Instance || i.Request.BeforeRevision != wantRevision || i.Request.StartedBeforePoint != wantPoint || i.Request.ConnectionIDs != nil {
				return fmt.Errorf("unfenced cap intent: %+v", i)
			}
		}
		return nil
	}
	for pos := start; pos < len(trace.Entries); {
		entry := trace.Entries[pos]
		var v map[string]any
		if err := json.Unmarshal(entry.Value, &v); err != nil {
			t.Fatal(err)
		}
		switch entry.Kind {
		case "helper-line":
			var input struct{ Line string }
			_ = json.Unmarshal(entry.Value, &input)
			var counters struct {
				Adapters []struct {
					Alias  string
					RX, TX float64
				}
			}
			if err := json.Unmarshal([]byte(input.Line), &counters); err != nil {
				t.Fatal(err)
			}
			if len(counters.Adapters) != 2 || !c.HelperLine([]byte(input.Line)) {
				t.Fatal("physical input rejected")
			}
			for _, a := range counters.Adapters {
				m, ok := c.meters[a.Alias]
				if !ok || m.counter.RX != a.RX || m.counter.TX != a.TX || m.at != clock.Now().UnixMilli() {
					t.Fatal("physical worker input", a, m)
				}
			}
			if err := cmp.Effects(); err != nil {
				t.Fatal(err)
			}
			checked[pos] = "physical worker counters accepted"
			pos++
		case "clock-tick":
			var tick struct{ Now int64 }
			_ = json.Unmarshal(entry.Value, &tick)
			if tick.Now < clock.Now().UnixMilli() || tick.Now > lastPoll+1000 {
				t.Fatal("poll deadline/order", tick.Now, lastPoll)
			}
			if tick.Now == lastPoll {
				if clock.Now().UnixMilli() != tick.Now || reads != polls {
					t.Fatal("same-time barrier has unfinished poll")
				}
				if err := cmp.Effects(); err != nil {
					t.Fatal(err)
				}
				checked[pos] = "same-time completed poll barrier"
				pos++
				continue
			}
			clock.at = time.UnixMilli(tick.Now)
			lastPoll = tick.Now
			polls++
			end := pos + 1
			for end < len(trace.Entries) && trace.Entries[end].Kind != "clock-tick" && trace.Entries[end].Kind != "helper-line" && trace.Entries[end].Kind != "http" {
				end++
			}
			logsAt, eventsAt, effectAt := len(files.logs), len(files.events), len(files.order)
			before := e.Snapshot()
			want := twoLineNativeConfig(map[string]string{})
			if polls == 2 {
				want.Blocked = []string{"b2"}
				want.Shares = map[string]uint64{"a1": 500000}
			}
			e.want = want
			// Startup's journal/settings guard remains installed: physical usage
			// must never mutate the user's saved settings.
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.guardError != nil {
				t.Fatal("usage native revision", e.guardError)
			}
			order := []string{"native:connections"}
			if polls == 2 {
				order = []string{"event", "log", "event", "log", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "write:control-journal.json", "write:control-journal.json.bak", "blocked-log", "native:connections"}
				if e.Snapshot().AppliedRevision <= before.AppliedRevision || e.Snapshot().AppliedPoint <= before.AppliedPoint {
					t.Fatal("cap revision not acknowledged")
				}
				exhaustedPoint = e.Snapshot().AppliedPoint
			}
			if resetTrace && polls == 3 {
				order = []string{"event", "log", "event", "log", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "native:connections", "native:close", "write:control-journal.json", "write:control-journal.json.bak"}
			}
			if err := cmp.Effects(order...); err != nil {
				t.Fatal("poll native ordering", err, files.order[effectAt:])
			}
			if reads != polls {
				t.Fatal("physical poll read count", reads, polls)
			}
			for _, owner := range []string{"", `c:\apps\firefox.exe`} {
				d, err := e.active.Decide(platform.Owner{AppID: owner}, 40000, false, 1)
				if err != nil || d.Line != "a1" {
					t.Fatal("exhausted main exception", d, err)
				}
			}
			// Independent physical totals: the first sample is a baseline.
			bytes := float64(0)
			if polls == 2 {
				bytes = 200
			}
			for _, line := range []string{"a1", "b2"} {
				if got := c.usage.Used(line); got == nil || got.Bytes != bytes {
					t.Fatal("physical usage delta", line, got, bytes)
				}
			}
			counterparts := &startupCounterparts{cmp: cmp}
			find := func(key string) int {
				for i := effectAt; i < len(files.order); i++ {
					if files.order[i] == key {
						return i
					}
				}
				return -1
			}
			logSources := []int{}
			for i := effectAt; i < len(files.order); i++ {
				if files.order[i] == "log" || files.order[i] == "blocked-log" {
					logSources = append(logSources, i)
				}
			}
			add := func(kind, id string, source int) {
				counterparts.want = append(counterparts.want, startupCounterpart{kind, id, source})
			}
			if polls == 2 || resetTrace && polls == 3 {
				for i := 0; i < 2; i++ {
					add("log", "", logSources[i])
				}
				for i := 0; i < 2; i++ {
					add("async-result", "log.append", logSources[i])
				}
			}
			add("engine", "GET /connections", find("native:connections"))
			add("engine-reply", "/connections", find("native:connections"))
			if resetTrace && polls == 3 {
				add("engine", "GET /connections", find("native:close"))
				add("engine-reply", "/connections", find("native:close"))
			}
			add("async-result", "engine./connections.json", find("native:connections"))
			if resetTrace && polls == 3 {
				add("async-result", "engine./connections.json", find("native:close"))
			}
			if polls == 2 {
				add("log", "", logSources[2])
				add("async-result", "log.append", logSources[2])
			}
			logIndex, eventIndex := logsAt, eventsAt
			pending := []string{}
			checked[pos] = "one native Poll and Supervise at deadline"
			for seq := pos + 1; seq < end; seq++ {
				x := trace.Entries[seq]
				if err := counterparts.Observe(x); err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				_ = json.Unmarshal(x.Value, &value)
				guard := ""
				switch x.Kind {
				case "counter-sample":
					alias, _ := value["alias"].(string)
					m, ok := c.meters[alias]
					if !ok || !reflect.DeepEqual(value["value"], map[string]any{"rx": m.counter.RX, "tx": m.counter.TX}) {
						t.Fatal("poll physical observation", x)
					}
					guard = "physical counter sample and independent delta"
				case "event":
					if eventIndex >= len(files.events) {
						t.Fatal("missing cap event")
					}
					actual := files.events[eventIndex].(map[string]any)
					oldID, newID := value["id"].(string), actual["id"].(string)
					if ids[oldID] != "" || reverse[newID] != "" || !generated[newID] {
						t.Fatal("event ID bijection", oldID, newID)
					}
					ids[oldID], reverse[newID] = newID, oldID
					value["id"] = newID
					if !reflect.DeepEqual(value, actual) {
						t.Fatal("cap event", value, actual)
					}
					t.Logf("event identity %s -> %s", oldID, newID)
					eventIndex++
					guard = "native generated event bijection and full value"
				case "log":
					text := value["text"].(string)
					if logIndex >= len(files.logs) || files.logs[logIndex] != text {
						t.Fatal("cap diagnostic", text, files.logs[logsAt:])
					}
					pending = append(pending, text)
					logIndex++
					guard = "ordered cap diagnostic"
				case "async-result":
					if value["ok"] != true {
						t.Fatal("unexpected async failure")
					}
					switch value["operation"] {
					case "log.append":
						if len(pending) == 0 || value["undefined"] != true || value["value"] != nil || !reflect.DeepEqual(value["args"], []any{pending[0]}) {
							t.Fatal("cap log completion", value)
						}
						pending = pending[1:]
					case "engine./connections.json":
						if value["undefined"] != false || !reflect.DeepEqual(value["args"], []any{}) || !reflect.DeepEqual(value["value"], map[string]any{"connections": []any{}}) {
							t.Fatal("empty flow observation", value)
						}
					default:
						t.Fatal("unmapped async result", x)
					}
					guard = "completed ordered native counterpart"
				case "engine":
					if value["route"] != "/connections" || value["method"] != "GET" {
						t.Fatal("unmapped engine operation", x)
					}
					guard = "actual native connection observation"
				case "engine-reply":
					if value["route"] != "/connections" || value["status"] != float64(200) || !reflect.DeepEqual(value["body"], map[string]any{"connections": []any{}}) {
						t.Fatal("connection result", value)
					}
					guard = "actual empty native connection result"
				case "write", "file-completion":
					file, _ := value["file"].(string)
					base := filepath.Base(file)
					if !(strings.HasPrefix(base, "apps-") || strings.HasPrefix(base, "share-") || strings.HasPrefix(base, "cut-")) || (polls != 2 && !(resetTrace && polls == 3)) {
						t.Fatal("unmapped poll file", x)
					}
					if x.Kind == "file-completion" && (value["ok"] != true || (value["operation"] != "writeFile" && value["operation"] != "rename")) {
						t.Fatal("rule completion", x)
					}
					guard = "complete acknowledged blocked policy replaces rule file"
				case "completion":
					if seq == 0 || value["kind"] != trace.Entries[seq-1].Kind || checked[seq-1] == "" {
						t.Fatal("unproved completion", x)
					}
					guard = checked[seq-1] + " completed"
				default:
					t.Fatal("unmapped poll entry", x)
				}
				checked[seq] = guard
			}
			if err := counterparts.Finish(); err != nil {
				t.Fatal(err)
			}
			if logIndex != len(files.logs) || eventIndex != len(files.events) || len(pending) != 0 {
				t.Fatal("unconsumed cap observations")
			}
			pos = end
		case "http":
			// Translate only previously established event IDs, never timestamps,
			// counters, text, ordering or unrelated resource identities.
			for i := range cmp.entries {
				if cmp.entries[i].Seq < pos {
					continue
				}
				value, err := rewriteTraceStrings(cmp.entries[i].Value, func(s string) string {
					if mapped := ids[s]; mapped != "" {
						return mapped
					}
					return s
				})
				if err != nil {
					t.Fatal(err)
				}
				cmp.entries[i].Value = value
			}
			end := pos + 1
			for end < len(trace.Entries) && trace.Entries[end].Kind != "api" {
				end++
			}
			if end == len(trace.Entries) {
				t.Fatal("missing response")
			}
			guard := replayStartupHTTP(t, c, entry, trace.Entries[end], cmp)
			checked[pos], checked[end] = guard, guard
			for seq := pos + 1; seq < end; seq++ {
				x := trace.Entries[seq]
				var snapshot struct {
					Now  int64
					Kind string
				}
				_ = json.Unmarshal(x.Value, &snapshot)
				if x.Kind == "state-snapshot" && snapshot.Now == clock.Now().UnixMilli() {
					checked[seq] = "HTTP response constructed at scenario clock"
				} else if x.Kind == "completion" && snapshot.Kind == trace.Entries[seq-1].Kind && checked[seq-1] != "" {
					checked[seq] = checked[seq-1] + " completed"
				} else {
					t.Fatal("unmapped HTTP observation", x)
				}
			}
			pos = end + 1
		default:
			t.Fatal("unmapped usage input", entry)
		}
	}
	wantPolls, wantEvents, wantCloses := 2, 2, 0
	if resetTrace {
		wantPolls, wantEvents, wantCloses = 4, 4, 1
	}
	if polls != wantPolls || reads != wantPolls || clock.Now().Sub(origin) != time.Duration(wantPolls)*time.Second || len(ids) != wantEvents || closes != wantCloses {
		t.Fatal("usage replay cardinality", polls, reads, len(ids))
	}
	for _, write := range files.writes[initialWrites:] {
		if strings.Contains(write.Path, "usage") {
			t.Fatal("unexpected usage persistence", write)
		}
	}
	if _, ok := files.data[filepath.Join("/test", "usage.recovery.json")]; ok {
		t.Fatal("unexpected recovery file")
	}
	if err := fileCursor.skipNative(); err != nil {
		t.Fatal(err)
	}
	return checked
}
