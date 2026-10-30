package control

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

func replayNativeRoutingReads(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fc *startupFileCursor) map[int]string {
	t.Helper()
	before, origin := e.Snapshot(), clock.Now()
	if before.Status != "on" || !c.WantsRouting() || c.quitting || c.ctx.Err() != nil || e.applies != 1 || e.probes.Load() != 2 {
		t.Fatal("routing/read starting state")
	}
	session, err := files.peekFile(filepath.Join("/test", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	logsAt := len(files.logs)
	var mu sync.Mutex
	stops, installed, reads := 0, 0, 0
	p := c.op.Platform.(*fakePlatform)
	p.mu.Lock()
	p.override = func(name string, _ map[string]any) (any, error, bool) {
		if name != "installed-apps" {
			return nil, nil, false
		}
		mu.Lock()
		installed++
		mu.Unlock()
		return []any{map[string]any{"path": `C:\Apps\Firefox.exe`, "name": "Firefox", "hasIcon": false}}, nil, true
	}
	p.mu.Unlock()
	e.readConnections = func(context.Context) ([]engine.Connection, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		return nil, fmt.Errorf("off routing must not read engine connections")
	}
	e.stopCheck = func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			b, err := files.peekFile(filepath.Join("/test", name))
			if err != nil {
				return err
			}
			var j struct{ Wanted bool }
			if err := json.Unmarshal(b, &j); err != nil {
				return err
			}
			if j.Wanted {
				return fmt.Errorf("routing stop before off intent")
			}
		}
		if e.Snapshot().Status != "on" || c.WantsRouting() || c.quitting || c.ctx.Err() != nil {
			return fmt.Errorf("routing stop precondition")
		}
		stops++
		files.recordOrder("native:stop")
		e.mu.Lock()
		e.calls = append(e.calls, "stop")
		e.s = engine.Snapshot{Status: "off", Instance: before.Instance, Policy: engine.Policy{}}
		e.mu.Unlock()
		e.active = nil
		files.recordOrder("native:stopped")
		return nil
	}
	checked := map[int]string{}
	var pendingMu sync.Mutex
	var pendingProbe func()
	http := func(begin, end int, effects ...string) {
		if begin == 182 {
			replayNativeHTTP(t, c, trace, cmp, begin, end, func() {
				pendingMu.Lock()
				fn := pendingProbe
				pendingProbe = nil
				pendingMu.Unlock()
				if fn == nil || !c.lanes["b2"].probing || c.lanes["b2"].delay != nil {
					t.Fatal("response snapshot must precede b2 completion")
				}
				files.recordOrder("snapshot")
				fn()
			})
		} else {
			replayNativeHTTP(t, c, trace, cmp, begin, end)
		}
		files.recordOrder("api")
		if err := cmp.Effects(append(effects, "api")...); err != nil {
			t.Fatal(err)
		}
		checked[begin], checked[end] = "actual HTTP request", "complete HTTP response"
	}
	http(135, 136)
	http(137, 140, "platform:installed-apps", "platform:app-info")
	http(141, 142)
	http(143, 164, "write:control-journal.json", "write:control-journal.json.bak", "log", "native:stop", "native:stopped", "log")
	if e.Snapshot().Status != "off" || c.WantsRouting() || c.quitting || c.ctx.Err() != nil || len(files.removes) != 0 {
		t.Fatal("routing off incorrectly quit Control")
	}
	for i := 1; i <= 2; i++ {
		clock.at = origin.Add(time.Duration(i) * time.Second)
		if err := c.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := c.Supervise(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := cmp.Effects(); err != nil {
			t.Fatal("off tick effects", err)
		}
		if e.Snapshot().Status != "off" || c.WantsRouting() || len(c.meters) != 0 {
			t.Fatal("off tick changed routing or invented counters")
		}
	}
	http(178, 181)
	// The startup-only usage callback has completed. A later Start has no
	// historical usage save, and the real Control request owns the new revision.
	e.beforeStart = nil
	var requests []engine.ProbeRequest
	var results []engine.ProbeResult
	e.probeBegin = func(r engine.ProbeRequest) { mu.Lock(); defer mu.Unlock(); requests = append(requests, r) }
	e.probeCheck = func(_ engine.ProbeRequest, r engine.ProbeResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	}
	c.op.ProbeBackground = func(line string, run func()) {
		fn := func() {
			files.recordOrder("native:probe:" + line)
			run()
			files.recordOrder("native:probe-result:" + line)
		}
		if line == "b2" {
			pendingMu.Lock()
			defer pendingMu.Unlock()
			if pendingProbe != nil {
				t.Fatal("duplicate pending probe")
			}
			pendingProbe = fn
		} else {
			fn()
		}
	}
	effectAt := cmp.effectNext
	http(182, 263, "write:control-journal.json", "write:control-journal.json.bak", "write:control-journal.json", "write:control-journal.json.bak", "native:desired", "log", "native:start", "native:apply", "native:ack", "native:started", "log", "lane-log", "lane-log", "native:probe:a1", "native:probe-result:a1", "snapshot", "native:probe:b2", "native:probe-result:b2")
	proof, err := fc.CheckRevision(trace.Entries[192:212], twoLineRevisionFiles(), cmp, effectAt)
	if err != nil {
		t.Fatal(err)
	}
	for seq, guard := range proof {
		checked[seq] = guard
	}
	http(264, 267)
	mu.Lock()
	defer mu.Unlock()
	if stops != 1 || installed != 1 || reads != 0 || e.applies != 2 || e.probes.Load() != 4 || e.Snapshot().Status != "on" || !c.WantsRouting() || c.ctx.Err() != nil || c.quitting || len(files.events) != 0 || len(files.removes) != 0 {
		t.Fatal("routing/read effect exhaustion", stops, installed, reads)
	}
	if len(requests) != 2 || len(results) != 2 || requests[0].OperationID == requests[1].OperationID {
		t.Fatal("restart physical probe identities")
	}
	for i, r := range requests {
		v := results[i]
		if r.OperationID == "" || r.Line != []string{"a1", "b2"}[i] || !r.Quick || r.Custom || r.Index != 0 || r.Target != "8.8.8.8:443" || v.Instance != e.Snapshot().Instance || v.Kind != "quick" || v.Outcome != engine.OK || v.Delay == nil || *v.Delay != 18 {
			t.Fatal("restart physical probe", r, v)
		}
	}
	if !reflect.DeepEqual(files.logs[logsAt:], []string{"routing stopping", "routing off", "routing starting", "routing on", "Ethernet's apps now use Ethernet", "Wi-Fi's apps now use Wi-Fi"}) {
		t.Fatal("routing diagnostic order", files.logs[logsAt:])
	}
	got, err := files.peekFile(filepath.Join("/test", "server.json"))
	if err != nil || !reflect.DeepEqual(got, session) {
		t.Fatal("routing replaced session", err)
	}
	// The retired start protocol has exactly the same ordered plan as the
	// already established native startup; only its second application is new.
	plan := nativeLiveRestartPlan(t, clock, "hungEngine", "unused")
	start := 0
	for i, x := range plan {
		if x.Kind == "log" && reflect.DeepEqual(replayJSON(t, x.Value), map[string]any{"text": "routing starting"}) {
			start = i
			break
		}
	}
	if start == 0 {
		t.Fatal("missing start plan")
	}
	part := trace
	part.Entries = trace.Entries[:263]
	if !reflect.DeepEqual(replayJSON(t, trace.Entries[259].Value), map[string]any{"now": float64(clock.Now().UnixMilli())}) {
		t.Fatal("restart response snapshot time")
	}
	checked[259] = "state snapshot after restart acknowledgement"
	checkNativeLiveEntries(t, part, clock, fc, 182, 216, 222, twoLineNativeConfig(map[string]string{}), checked, plan[start:])
	// Check the prefix's values and order; usage and session deletion are absent.
	prefix := []traceEntry{}
	add := func(kind string, v any) {
		prefix = append(prefix, traceEntry{Kind: kind, Value: mustStartupJSON(t, v)})
	}
	async := func(op string, args []any, value any, undefined bool) {
		add("async-result", map[string]any{"operation": op, "args": args, "ok": true, "value": value, "undefined": undefined})
	}
	async("installedApps.list", []any{}, []any{map[string]any{"path": `C:\Apps\Firefox.exe`, "name": "Firefox", "hasIcon": false}}, false)
	add("log", map[string]any{"text": "routing stopping"})
	add("process-exit", map[string]any{"pid": 456, "code": 0})
	add("remove", map[string]any{"file": "/oracle/data/engine.pid"})
	async("log.append", []any{"routing stopping"}, nil, true)
	for i := 0; i < 2; i++ {
		if i == 1 {
			add("remove", map[string]any{"file": "/oracle/data/engine.pid"})
		}
		add("file-completion", map[string]any{"operation": "rm", "file": "/oracle/data/engine.pid", "ok": true})
	}
	add("log", map[string]any{"text": "routing off"})
	async("log.append", []any{"routing off"}, nil, true)
	add("state-snapshot", map[string]any{"now": origin.UnixMilli()})
	for i := 0; i < 2; i++ {
		async("platform.readDefaultRoutes", []any{}, c.routes, false)
	}
	for i := 1; i <= 2; i++ {
		now := origin.Add(time.Duration(i) * time.Second).UnixMilli()
		add("clock-tick", map[string]any{"now": now})
		for _, alias := range []string{"Ethernet", "Wi-Fi"} {
			add("counter-sample", map[string]any{"alias": alias, "value": nil})
		}
		add("clock-tick", map[string]any{"now": now})
	}
	add("clock-tick", map[string]any{"now": clock.Now().UnixMilli()})
	add("state-snapshot", map[string]any{"now": clock.Now().UnixMilli()})
	completion, next := 56, 0
	for _, x := range trace.Entries[135:182] {
		if x.Kind == "completion" {
			completion = checkHealthCompletion(t, trace, x.Seq, completion, checked)
			continue
		}
		if checked[x.Seq] != "" {
			continue
		}
		if next == len(prefix) || x.Kind != prefix[next].Kind || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, prefix[next].Value)) {
			t.Fatalf("routing prefix at %d/%s, plan %d", x.Seq, x.Kind, next)
		}
		next++
		checked[x.Seq] = "ordered read/off observation with surviving Control session"
	}
	if next != len(prefix) {
		t.Fatal("unconsumed routing prefix")
	}
	if !reflect.DeepEqual(replayJSON(t, trace.Entries[265].Value), map[string]any{"now": float64(clock.Now().UnixMilli())}) {
		t.Fatal("final routing snapshot")
	}
	checked[265] = "final state at unchanged clock"
	checkHealthCompletion(t, trace, 266, 102, checked)
	return checked
}
