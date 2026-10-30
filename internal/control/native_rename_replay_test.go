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

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

func replayNativeRename(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fc *startupFileCursor) map[int]string {
	t.Helper()
	checked := map[int]string{}
	before := e.Snapshot()
	items := c.itemsLocked()
	if len(items) != 2 || items[0].Alias != "Ethernet" || items[0].GUID == nil || *items[0].GUID != "adapter-0" || items[1].GUID == nil || *items[1].GUID != "adapter-1" || e.applies != 1 {
		t.Fatal("rename initial identity/policy")
	}
	var adapters []map[string]any
	if err := json.Unmarshal(trace.Entries[135].Value, &adapters); err != nil {
		t.Fatal(err)
	}
	var interfaces map[string][]map[string]any
	if err := json.Unmarshal(trace.Entries[136].Value, &interfaces); err != nil {
		t.Fatal(err)
	}
	p := c.op.Platform.(*fakePlatform)
	worker := []any{}
	for _, raw := range adapters {
		a := map[string]any{}
		for k, v := range raw {
			a[k] = v
		}
		a["status"], a["gateway"] = "Up", "192.0.2.254"
		if a["kind"] == "wifi" {
			a["mediaType"] = "wireless"
		}
		ips := []any{}
		for _, ip := range interfaces[a["alias"].(string)] {
			if ip["family"] == "IPv4" && ip["internal"] == false {
				ips = append(ips, ip["address"])
			}
		}
		if !reflect.DeepEqual(ips, raw["ipv4s"]) {
			t.Fatal("rename physical input addresses")
		}
		worker = append(worker, a)
	}
	p.network = map[string]any{"adapters": worker, "defaultRoutes": p.network["defaultRoutes"], "policy": c.policy, "readAt": float64(clock.Now().UnixMilli())}
	if c.itemsLocked()[0].Alias != "Ethernet" || e.Snapshot().AppliedRevision != before.AppliedRevision {
		t.Fatal("staging rename changed Control")
	}
	checked[135], checked[136] = "staged physical adapter identity", "staged physical addresses"
	logs := len(files.logs)
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cmp.Effects("platform:network", "write:control-journal.json", "write:control-journal.json.bak", "write:settings.json", "write:settings.json.bak", "log"); err != nil {
		t.Fatal("rename persistence", err)
	}
	if c.itemsLocked()[0].ID != "a1" || c.itemsLocked()[0].Alias != "LAN" || c.itemsLocked()[0].GUID == nil || *c.itemsLocked()[0].GUID != "adapter-0" || e.Snapshot().AppliedRevision != before.AppliedRevision || len(files.logs) != logs+1 || files.logs[logs] != "Ethernet's adapter was renamed from Ethernet to LAN" {
		t.Fatal("GUID reconciliation before apply")
	}
	checked[137] = "real refresh reconciles GUID and persists rename before apply"
	var wantSettings struct{ Text string }
	_ = json.Unmarshal(trace.Entries[144].Value, &wantSettings)
	e.want = twoLineNativeConfig(map[string]string{})
	e.want.Lines[0].Interface = "LAN"
	e.check = func(r engine.Revision) error {
		for _, name := range []string{"settings.json", "settings.json.bak"} {
			if !reflect.DeepEqual(replayJSON(t, files.data[filepath.Join("/test", name)]), replayJSON(t, []byte(wantSettings.Text))) {
				return fmt.Errorf("rename settings not durable: %s", name)
			}
		}
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			var j struct {
				Desired  engine.Revision
				Settings any
				Wanted   bool
			}
			if err := json.Unmarshal(files.data[filepath.Join("/test", name)], &j); err != nil {
				return err
			}
			if !j.Wanted || !reflect.DeepEqual(j.Desired, r) || !reflect.DeepEqual(j.Settings, replayJSON(t, []byte(wantSettings.Text))) {
				return fmt.Errorf("rename journal not durable: %s", name)
			}
		}
		return nil
	}
	var mu sync.Mutex
	requests := []engine.ProbeRequest{}
	results := []engine.ProbeResult{}
	e.probeBegin = func(r engine.ProbeRequest) { mu.Lock(); defer mu.Unlock(); requests = append(requests, r) }
	e.probeCheck = func(_ engine.ProbeRequest, r engine.ProbeResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	}
	reads := 0
	e.readConnections = func(context.Context) ([]engine.Connection, error) {
		reads++
		files.recordOrder("native:connections")
		return []engine.Connection{}, nil
	}
	var tick struct{ Now int64 }
	_ = json.Unmarshal(trace.Entries[155].Value, &tick)
	if tick.Now != clock.Now().UnixMilli()+1000 {
		t.Fatal("rename poll deadline")
	}
	clock.at = time.UnixMilli(tick.Now).UTC()
	from := cmp.effectNext
	calls := len(e.calls)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.guardError != nil {
		t.Fatal(e.guardError)
	}
	if err := cmp.Effects("write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "lane-log", "native:connections", "native:probe:a1", "native:probe-result:a1"); err != nil {
		t.Fatal("rename live poll", err)
	}
	if !reflect.DeepEqual(e.calls[calls:], []string{"apply"}) || e.Snapshot().Instance != before.Instance || reads != 1 || len(requests) != 1 || len(results) != 1 {
		t.Fatal("rename retained session and exactly one physical probe", e.calls[calls:], requests, results)
	}
	r, v := requests[0], results[0]
	if r.Line != "a1" || r.OperationID == "" || !r.Quick || r.Target != "8.8.8.8:443" || r.Index != 0 || v.Outcome != engine.OK || v.Kind != "quick" || v.Instance != before.Instance || v.Delay == nil || *v.Delay != 18 {
		t.Fatal("renamed line physical check", r, v)
	}
	if len(files.logs) != logs+2 || files.logs[logs+1] != "Ethernet's apps now use Ethernet" {
		t.Fatal("rename native diagnostics", files.logs[logs:])
	}
	actualBefore, err := engine.NativeRevision(engine.Revision{Number: before.AppliedRevision, Policy: before.Policy}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	after := e.Snapshot()
	actualAfter, err := engine.NativeRevision(engine.Revision{Number: after.AppliedRevision, Policy: after.Policy}, apppath.Windows)
	if err != nil {
		t.Fatal(err)
	}
	checkLiveOrderHeldFlows(t, actualBefore.Config, actualAfter.Config)
	proof, err := fc.CheckRevision(trace.Entries[207:227], twoLineRevisionFiles(), cmp, from)
	if err != nil {
		t.Fatal(err)
	}
	for seq, guard := range proof {
		checked[seq] = guard
	}
	// Ordered projection for the refresh and the one completed native poll.
	values := []traceEntry{}
	add := func(kind string, value any) {
		values = append(values, traceEntry{Kind: kind, Value: mustStartupJSON(t, value)})
	}
	async := func(op string, args []any, value any, undefined bool) {
		add("async-result", map[string]any{"operation": op, "args": args, "ok": true, "value": value, "undefined": undefined})
	}
	add("adapter-snapshot", adapters)
	async("platform.detectAdapters", []any{}, adapters, false)
	add("log", map[string]any{"text": files.logs[logs]})
	async("log.append", []any{files.logs[logs]}, nil, true)
	for _, alias := range []string{"LAN", "Wi-Fi"} {
		if _, ok := c.meters[alias]; ok {
			t.Fatal("invented rename counter")
		}
		add("counter-sample", map[string]any{"alias": alias, "value": nil})
	}
	async("platform.readDefaultRoutes", []any{}, c.routes, false)
	add("engine", map[string]any{"route": "/proxies/lane-a1", "method": "PUT", "body": map[string]any{"name": "line-a1"}})
	add("engine-reply", map[string]any{"route": "/proxies/lane-a1", "status": 200, "body": map[string]any{}})
	add("engine", map[string]any{"route": "/proxies/line-a1/delay", "method": "GET"})
	add("probe-result", map[string]any{"route": "/proxies/line-a1/delay", "status": 200, "body": map[string]any{"delay": *v.Delay}})
	add("log", map[string]any{"text": files.logs[logs+1]})
	async("engine./proxies/line-a1/delay.json", []any{}, map[string]any{"delay": *v.Delay}, false)
	async("log.append", []any{files.logs[logs+1]}, nil, true)
	add("probe-vote", map[string]any{"line": "a1", "result": true, "at": tick.Now})
	add("engine", map[string]any{"route": "/connections", "method": "GET"})
	add("engine-reply", map[string]any{"route": "/connections", "status": 200, "body": map[string]any{"connections": []any{}}})
	async("engine./connections.json", []any{}, map[string]any{"connections": []any{}}, false)
	next := 0
	for seq := 138; seq < 181; seq++ {
		x := trace.Entries[seq]
		if x.Kind == "completion" || x.Kind == "write" || x.Kind == "file-completion" {
			continue
		}
		if x.Kind == "clock-tick" {
			if !reflect.DeepEqual(replayJSON(t, x.Value), map[string]any{"now": float64(tick.Now)}) {
				t.Fatal("rename duplicate deadline")
			}
			checked[seq] = "same-time completed poll barrier"
			continue
		}
		if next >= len(values) || x.Kind != values[next].Kind || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, values[next].Value)) {
			t.Fatal("ordered rename observation", seq, x.Kind, next)
		}
		next++
		checked[seq] = "exact observation from reconciled native refresh/poll"
	}
	if next != len(values) {
		t.Fatal("rename observation leftovers")
	}
	guard := replayStartupHTTP(t, c, trace.Entries[277], trace.Entries[280], cmp)
	checked[277], checked[280] = guard, guard
	if !reflect.DeepEqual(replayJSON(t, trace.Entries[276].Value), map[string]any{"now": float64(tick.Now)}) {
		t.Fatal("restart replacement time")
	}
	checked[276] = "live revision completed without restart or clock advance"
	plan := nativeLiveRestartPlan(t, clock, "adapterRename", "routing restarts to use LAN, Wi-Fi")
	return checkNativeLiveEntries(t, trace, clock, fc, 134, 231, 237, e.want, checked, plan)
}
