package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
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
	movedTrace := trace.Name == "capMoved"
	var supplied []engine.Connection
	wireConnections := any([]any{})
	flowIDs := map[string]string{}
	stableSettings := replayJSON(t, files.data[filepath.Join("/test", "settings.json")])
	var exhaustedPoint uint64
	closes := 0
	base := e.fakeEngine
	base.readConnections = func(context.Context) ([]engine.Connection, error) {
		reads++
		files.recordOrder("native:connections")
		return append([]engine.Connection{}, supplied...), nil
	}
	e.closeCheck = func(r engine.CloseRequest) (engine.CloseResult, error) {
		wantPoll := 3
		if movedTrace {
			wantPoll = 2
			exhaustedPoint = e.Snapshot().AppliedPoint
		}
		if (!resetTrace && !movedTrace) || polls != wantPoll || r.Line != "b2" || r.Instance != e.Snapshot().Instance || r.StartedBeforePoint != exhaustedPoint || r.ConnectionIDs != nil || r.OperationID == "" || !generated[r.OperationID] {
			return engine.CloseResult{}, fmt.Errorf("unfenced reset closure: %+v", r)
		}
		files.recordOrder("native:close")
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			var j struct{ Closures []closureIntent }
			if err := json.Unmarshal(files.data[filepath.Join("/test", name)], &j); err != nil {
				t.Fatal(err)
			}
			if len(j.Closures) != 1 || !reflect.DeepEqual(j.Closures[0].Request, r) {
				t.Fatal("closure lacks durable acknowledged cutoff", name, j.Closures, r)
			}
		}
		closes++
		if movedTrace {
			return engine.CloseResult{Closed: checkNativePhysicalClosure(t, supplied, r, e.want)}, nil
		}
		return engine.CloseResult{}, nil
	}
	lastPoll := origin.UnixMilli()
	e.check = func(r engine.Revision) error {
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			var j struct {
				Closures []closureIntent
				Desired  engine.Revision
				Settings any
				Wanted   bool
			}
			if err := json.Unmarshal(files.data[filepath.Join("/test", name)], &j); err != nil {
				return err
			}
			if !j.Wanted || !reflect.DeepEqual(j.Desired, r) || !reflect.DeepEqual(replayJSON(t, files.data[filepath.Join("/test", "settings.json")]), stableSettings) {
				return fmt.Errorf("%s changed usage settings or lacks desired revision", name)
			}
			for key, value := range stableSettings.(map[string]any) {
				if !reflect.DeepEqual(j.Settings.(map[string]any)[key], value) {
					return fmt.Errorf("%s changed saved setting %s", name, key)
				}
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
		if err := json.Unmarshal(entry.Value, &v); err != nil && entry.Kind != "connections" {
			t.Fatal(err)
		}
		switch entry.Kind {
		case "connections":
			if len(supplied) != 0 || polls != 1 {
				t.Fatal("flow fixture starting state")
			}
			if err := json.Unmarshal(entry.Value, &supplied); err != nil {
				t.Fatal(err)
			}
			wireConnections = replayJSON(t, entry.Value)
			for i := range supplied {
				old := supplied[i].ID
				native := fmt.Sprintf("%s:%d", e.Snapshot().Instance, i+1)
				if old == "" || flowIDs[old] != "" {
					t.Fatal("duplicate flow identity")
				}
				flowIDs[old] = native
				supplied[i].ID = native
			}
			checked[pos] = "instance-scoped flow input bijection"
			pos++
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
			if polls >= 2 && !resetTrace || polls == 2 {
				want.Blocked = []string{"b2"}
				want.Shares = map[string]uint64{"a1": 500000}
				if movedTrace {
					want.Blocked = []string{}
					want.Shares = map[string]uint64{"a1": 500000, "b2": 500000}
					want.Lanes["b2"] = "a1"
				}
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
			if movedTrace && polls == 2 {
				order = []string{"event", "log", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "write:control-journal.json", "write:control-journal.json.bak", "lane-log", "native:connections", "platform:app-info", "native:close", "log", "write:control-journal.json", "write:control-journal.json.bak"}
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
			if polls == 2 || movedTrace && polls > 2 {
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
				if files.order[i] == "log" || files.order[i] == "blocked-log" || files.order[i] == "lane-log" {
					logSources = append(logSources, i)
				}
			}
			add := func(kind, id string, source int) {
				counterparts.want = append(counterparts.want, startupCounterpart{kind, id, source})
			}
			if polls == 2 || resetTrace && polls == 3 {
				n := 2
				if movedTrace {
					n = 1
				}
				for i := 0; i < n; i++ {
					add("log", "", logSources[i])
				}
				for i := 0; i < n; i++ {
					add("async-result", "log.append", logSources[i])
				}
			}
			if movedTrace && polls == 2 {
				add("engine", "PUT /proxies/lane-b2", find("native:ack"))
				add("engine-reply", "/proxies/lane-b2", find("native:ack"))
				add("log", "", logSources[1])
				add("async-result", "log.append", logSources[1])
			}
			add("engine", "GET /connections", find("native:connections"))
			add("engine-reply", "/connections", find("native:connections"))
			if resetTrace && polls == 3 || movedTrace && polls == 2 {
				add("engine", "GET /connections", find("native:close"))
				add("engine-reply", "/connections", find("native:close"))
			}
			add("async-result", "engine./connections.json", find("native:connections"))
			if resetTrace && polls == 3 || movedTrace && polls == 2 {
				add("async-result", "engine./connections.json", find("native:close"))
			}
			if polls == 2 {
				if movedTrace {
					add("engine", "DELETE /connections/phone-flow", find("native:close"))
					add("engine-reply", "/connections/phone-flow", find("native:close"))
				}
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
						if value["undefined"] != false || !reflect.DeepEqual(value["args"], []any{}) || !reflect.DeepEqual(value["value"], map[string]any{"connections": wireConnections}) {
							t.Fatal("empty flow observation", value)
						}
					default:
						t.Fatal("unmapped async result", x)
					}
					guard = "completed ordered native counterpart"
				case "engine":
					if movedTrace && polls == 2 && value["route"] == "/proxies/lane-b2" && value["method"] == "PUT" && reflect.DeepEqual(value["body"], map[string]any{"name": "line-a1"}) {
						guard = "acknowledged moved lane"
						break
					}
					if movedTrace && polls == 2 && value["route"] == "/connections/phone-flow" && value["method"] == "DELETE" && closes == 1 && flowIDs["phone-flow"] != "" {
						guard = "physical line and apply-point closure selected exact flow"
						break
					}
					if value["route"] != "/connections" || value["method"] != "GET" {
						t.Fatal("unmapped engine operation", x)
					}
					guard = "actual native connection observation"
				case "engine-reply":
					if movedTrace && polls == 2 && (value["route"] == "/proxies/lane-b2" || value["route"] == "/connections/phone-flow") && value["status"] == float64(200) && reflect.DeepEqual(value["body"], map[string]any{}) {
						guard = "completed native apply or closure"
						break
					}
					if value["route"] != "/connections" || value["status"] != float64(200) || !reflect.DeepEqual(value["body"], map[string]any{"connections": wireConnections}) {
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
			if v["method"] == "POST" {
				if v["route"] != "/api/lines/update" {
					t.Fatal("unexpected policy route")
				}
				settingsSeq := -1
				for seq := pos + 1; seq < end; seq++ {
					if trace.Entries[seq].Kind == "write" {
						var w struct{ File string }
						_ = json.Unmarshal(trace.Entries[seq].Value, &w)
						if filepath.Base(w.File) == "settings.json" {
							settingsSeq = seq
						}
					}
				}
				if settingsSeq < 0 {
					t.Fatal("missing durable cap settings")
				}
				guard := e.check
				want := twoLineNativeConfig(map[string]string{})
				for seq, proof := range replayNativePolicySteps(t, c, e, clock, files, trace, cmp, []nativePolicyStep{{pos, end, settingsSeq, want}}) {
					checked[seq] = proof
				}
				e.check = guard
				var write struct{ Text string }
				_ = json.Unmarshal(trace.Entries[settingsSeq].Value, &write)
				stableSettings = replayJSON(t, []byte(write.Text))
				for seq := pos + 1; seq < end; seq++ {
					x := trace.Entries[seq]
					var value map[string]any
					_ = json.Unmarshal(x.Value, &value)
					switch x.Kind {
					case "file-completion":
						matched, err := fileCursor.Observe(x)
						if err != nil {
							t.Fatal(err)
						}
						if !matched {
							file, _ := value["file"].(string)
							if value["ok"] != true || !(strings.Contains(file, "apps-") || strings.Contains(file, "share-") || strings.Contains(file, "cut-")) {
								t.Fatal("unmapped policy file", x)
							}
						}
						checked[seq] = "completed policy file or acknowledged native revision"
					case "write":
						file := filepath.Base(value["file"].(string))
						if file == "settings.json" || file == "settings.json.bak" {
							if err := fileCursor.Publication(file, []byte(value["text"].(string))); err != nil {
								t.Fatal(err)
							}
						} else if !(strings.HasPrefix(file, "apps-") || strings.HasPrefix(file, "share-") || strings.HasPrefix(file, "cut-")) {
							t.Fatal("unmapped policy publication", x)
						}
						checked[seq] = "durable setting or complete literal revision"
					case "completion":
						if value["kind"] != trace.Entries[seq-1].Kind || checked[seq-1] == "" {
							t.Fatal("unproved policy completion", x)
						}
						checked[seq] = checked[seq-1] + " completed"
					default:
						t.Fatal("unmapped policy observation", x)
					}
				}
				pos = end + 1
				continue
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
	if movedTrace {
		wantPolls, wantEvents, wantCloses = 3, 1, 1
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

// A real flow-table counterpart for the physical selector. Historical flows
// may have been admitted under earlier pins, independently of today's policy.
// The fixture's repeated connection inputs remain observation snapshots; they
// do not assert that a closed socket came back to life.
func checkNativePhysicalClosure(t *testing.T, input []engine.Connection, request engine.CloseRequest, current policy.Config) int {
	t.Helper()
	table := flows.New(flows.Defaults(), nil)
	t.Cleanup(table.CloseAll)
	var revision uint64
	apply := func(config policy.Config) policy.Applied {
		revision++
		a, err := table.Apply(policy.Revision{N: revision, Hash: policy.Hash(config), Config: config})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	for i, connection := range input {
		if len(connection.Chains) != 1 {
			t.Fatal("physical flow input", connection)
		}
		line := strings.TrimPrefix(connection.Chains[0], "line-")
		config := twoLineNativeConfig(map[string]string{connection.Metadata.ProcessPath: line})
		apply(config)
		ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(fmt.Sprintf("198.18.0.2:%d", 40000+i)), Destination: netip.MustParseAddrPort("203.0.113.9:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ticket.Resolve(platform.Owner{AppID: connection.Metadata.ProcessPath, Path: connection.Metadata.ProcessPath}); err != nil {
			t.Fatal(err)
		}
		ticket.Add(uint64(connection.Upload), uint64(connection.Download))
		ticket.SetCancel(ticket.Close)
	}
	before, err := table.Page("")
	if err != nil || len(before.Flows) != len(input) {
		t.Fatal("closure starting flows", before, err)
	}
	for i, flow := range before.Flows {
		if flow.Line != strings.TrimPrefix(input[i].Chains[0], "line-") || flow.Owner.Path != input[i].Metadata.ProcessPath || flow.Up != uint64(input[i].Upload) || flow.Down != uint64(input[i].Download) {
			t.Fatal("native flow bijection", flow, input[i])
		}
	}
	cutoff := apply(current).Point
	// A later reset can reopen b2 before a delayed closure is delivered. The
	// old cutoff must spare that new b2 flow, not merely spare another line.
	apply(twoLineNativeConfig(map[string]string{"new-b2": "b2"}))
	newLine, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:41001"), Destination: netip.MustParseAddrPort("203.0.113.11:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newLine.Resolve(platform.Owner{AppID: "new-b2"}); err != nil {
		t.Fatal(err)
	}
	newLine.SetCancel(newLine.Close)
	// A newer main flow must survive, as must every old unrelated main flow.
	newer, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:41000"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newer.Resolve(platform.Owner{AppID: "new-main"}); err != nil {
		t.Fatal(err)
	}
	newer.SetCancel(newer.Close)
	result, err := table.CloseFlows(flows.Selector{Line: request.Line}, cutoff)
	if err != nil || result.Failed != 0 || result.Gone != 0 {
		t.Fatal("native physical closure", result, err)
	}
	want := 0
	for _, flow := range before.Flows {
		if flow.Line == request.Line {
			want++
		}
	}
	if want == 0 || result.Closed != want {
		t.Fatal("exact selected native flows", result, want)
	}
	after, err := table.Page("")
	if err != nil || len(after.Flows) != len(input)-want+2 {
		t.Fatal("native closure survivors", after, err)
	}
	for _, flow := range after.Flows {
		if flow.Line == request.Line && flow.Point < cutoff {
			t.Fatal("old physical flow survived", flow)
		}
	}
	return result.Closed
}
