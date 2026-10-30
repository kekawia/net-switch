package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// SYSTEM-DESIGN 4.4/5.7: the old restart is replaced by a live revision,
// retaining the instance and held flows. This executes on the startup Core;
// the HTTP body, never the expected response, determines the new line order.
func replayNativeLiveOrder(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fc *startupFileCursor) map[int]string {
	t.Helper()
	before := e.Snapshot()
	oldConfig := twoLineNativeConfig(map[string]string{})
	if before.Status != "on" || before.AppliedRevision == 0 || !reflect.DeepEqual(e.want, oldConfig) || len(c.itemsLocked()) != 2 || c.itemsLocked()[0].ID != "a1" {
		t.Fatal("live reorder starting policy")
	}
	for _, id := range []string{"a1", "b2"} {
		l := c.lanes[id]
		if l.health.Up == nil || !*l.health.Up || l.probing || l.delay == nil || *l.delay != 18 {
			t.Fatal("live reorder starting health", id)
		}
	}
	want := twoLineNativeConfig(map[string]string{})
	want.Lines = []platform.Line{{ID: "b2", Interface: "Wi-Fi"}, {ID: "a1", Interface: "Ethernet"}}
	end, read, configSeq, pidSeq := 269, 270, 222, 228
	note := "line order: Wi-Fi, Ethernet"
	if trace.Name == "lineRemove" {
		want.Lines = []platform.Line{{ID: "a1", Interface: "Ethernet"}}
		want.Lanes = map[string]string{"a1": "a1"}
		want.Shares = map[string]uint64{}
		end, read, configSeq, pidSeq = 229, 230, 210, 216
		note = "removed Wi-Fi (Wi-Fi)"
	}
	calls := len(e.calls)
	checked := replayNativePolicySteps(t, c, e, clock, files, trace, cmp, fc, []nativePolicyStep{{135, end, 158, want}, {read, read + 3, -1, want}})
	if !reflect.DeepEqual(e.calls[calls:], []string{"apply"}) || e.Snapshot().Instance != before.Instance || e.Snapshot().Status != "on" {
		t.Fatal("live revision must retain engine instance without stop/start", e.calls[calls:])
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
	// Project the retired stop/start protocol in its original order, using
	// independent operation literals. Completion IDs are checked separately.
	plan := []traceEntry{}
	add := func(kind string, value any) {
		plan = append(plan, traceEntry{Kind: kind, Value: mustStartupJSON(t, value)})
	}
	async := func(op string, args []any, value any, undefined bool) {
		add("async-result", map[string]any{"operation": op, "args": args, "ok": true, "value": value, "undefined": undefined})
	}
	log := func(text string) {
		add("log", map[string]any{"text": text})
		async("log.append", []any{text}, nil, true)
	}
	file := func(op, name string, ok bool) {
		v := map[string]any{"operation": op, "file": "/oracle/data/" + name, "ok": ok}
		if !ok {
			v["code"] = "ENOENT"
		}
		add("file-completion", v)
	}
	remove := func(name string) { add("remove", map[string]any{"file": "/oracle/data/" + name}) }
	log(note)
	add("log", map[string]any{"text": "routing stopping"})
	add("process-exit", map[string]any{"pid": 456, "code": 0})
	remove("engine.pid")
	async("log.append", []any{"routing stopping"}, nil, true)
	file("rm", "engine.pid", true)
	remove("engine.pid")
	file("rm", "engine.pid", true)
	log("routing off")
	log("routing starting")
	file("readFile", "engine.pid", false)
	add("socket-completion", map[string]any{"operation": "listen", "port": 49000})
	add("socket-completion", map[string]any{"operation": "close", "port": 49000})
	names := []string{"settings.json", "server.json", "usage.json", "apps-a1.json", "apps-b2.json", "share-b2.json", "cut-b2.json", "engine-config.json", "settings.json.bak"}
	if trace.Name == "lineOrder" {
		names = append(names, "share-a1.json", "cut-a1.json")
	}
	add("directory-list", map[string]any{"directory": "/oracle/data", "names": names})
	file("readdir", "", true)
	// The directory is /oracle/data, without a trailing separator.
	plan[len(plan)-1].Value = mustStartupJSON(t, map[string]any{"operation": "readdir", "file": "/oracle/data", "ok": true})
	removed := []string{"share-b2.json", "cut-b2.json"}
	if trace.Name == "lineRemove" {
		removed = append([]string{"apps-b2.json"}, removed...)
	}
	for _, name := range removed {
		remove(name)
		file("rm", name, true)
	}
	// Config and PID publications below have their own semantic checks.
	file("writeFile", "engine-config.json", true)
	async("log.rotate", []any{}, nil, true)
	add("spawn", map[string]any{"exe": "/oracle/engine/sing-box.exe", "args": []string{"run", "-c", "/oracle/data/engine-config.json", "--disable-color"}})
	file("writeFile", "engine.pid", true)
	add("engine", map[string]any{"route": "/version", "method": "GET"})
	add("engine-reply", map[string]any{"route": "/version", "status": 200, "body": map[string]any{}})
	log("routing on")
	probeLines := []struct{ id, label string }{{"b2", "Wi-Fi"}, {"a1", "Ethernet"}}
	if trace.Name == "lineRemove" {
		probeLines = nil
	}
	for i, line := range probeLines {
		lane, probe := "/proxies/lane-"+line.id, "/proxies/line-"+line.id+"/delay"
		add("engine", map[string]any{"route": lane, "method": "PUT", "body": map[string]any{"name": "line-" + line.id}})
		add("engine-reply", map[string]any{"route": lane, "status": 200, "body": map[string]any{}})
		async("platform.readDefaultRoutes", []any{}, []map[string]string{{"interfaceAddress": "192.0.2.1"}, {"interfaceAddress": "192.0.2.2"}}, false)
		add("engine", map[string]any{"route": probe, "method": "GET"})
		add("probe-result", map[string]any{"route": probe, "status": 200, "body": map[string]any{"delay": 18}})
		if i == 1 {
			add("probe-vote", map[string]any{"line": "b2", "result": true, "at": clock.Now().UnixMilli()})
		}
		log(line.label + "'s apps now use " + line.label)
		async("engine."+probe+".json", []any{}, map[string]any{"delay": 18}, false)
	}
	if len(probeLines) > 0 {
		add("probe-vote", map[string]any{"line": "a1", "result": true, "at": clock.Now().UnixMilli()})
	} else {
		async("platform.readDefaultRoutes", []any{}, []map[string]string{{"interfaceAddress": "192.0.2.1"}, {"interfaceAddress": "192.0.2.2"}}, false)
	}
	next, completion := 0, 0
	for _, x := range trace.Entries[:135] {
		if x.Kind == "completion" {
			var v struct{ ID int }
			_ = json.Unmarshal(x.Value, &v)
			completion = v.ID
		}
	}
	for seq := 136; seq < len(trace.Entries); seq++ {
		x := trace.Entries[seq]
		if x.Kind == "completion" {
			completion = checkHealthCompletion(t, trace, seq, completion, checked)
			continue
		}
		if checked[seq] != "" {
			continue
		}
		if x.Kind == "state-snapshot" {
			if !reflect.DeepEqual(replayJSON(t, x.Value), map[string]any{"now": float64(clock.Now().UnixMilli())}) {
				t.Fatal("live response snapshot", seq)
			}
			checked[seq] = "response after acknowledged live revision at unchanged clock"
			continue
		}
		if x.Kind == "file-completion" {
			if matched, err := fc.Observe(x); matched {
				if err != nil {
					t.Fatal(err)
				}
				checked[seq] = "distinct durable live settings operation"
				continue
			}
		}
		if x.Kind == "write" {
			var v struct{ File, Text string }
			_ = json.Unmarshal(x.Value, &v)
			switch filepath.Base(v.File) {
			case "settings.json", "settings.json.bak":
				if err := fc.Publication(filepath.Base(v.File), []byte(v.Text)); err != nil {
					t.Fatal(err)
				}
			case "engine.pid":
				if v.Text != "456" || seq != pidSeq {
					t.Fatal("retired PID publication", seq)
				}
			case "engine-config.json":
				var config struct {
					Outbounds []map[string]any
					Route     struct{ Final string }
				}
				if err := json.Unmarshal([]byte(v.Text), &config); err != nil {
					t.Fatal(err)
				}
				final, outbounds := "lane-"+want.Lines[0].ID, 2*len(want.Lines)
				if len(want.Lines) == 1 {
					final = "line-a1"
					outbounds = 1
				}
				if seq != configSeq || len(config.Outbounds) != outbounds || config.Route.Final != final {
					t.Fatal("retired config line order")
				}
				for i, line := range want.Lines {
					if config.Outbounds[i]["tag"] != "line-"+line.ID || config.Outbounds[i]["bind_interface"] != line.Interface || len(want.Lines) > 1 && (config.Outbounds[i+2]["default"] != "line-"+want.Lanes[line.ID] || config.Outbounds[i+2]["interrupt_exist_connections"] != false) {
						t.Fatal("retired config binding/lane", i)
					}
				}
			default:
				t.Fatal("unproved live publication", seq)
			}
			checked[seq] = "live revision preserves held flows and replaces retired publication"
			continue
		}
		if next == len(plan) || x.Kind != plan[next].Kind || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, plan[next].Value)) {
			t.Fatalf("ordered live replacement at %d/%s, plan %d: %s", seq, x.Kind, next, x.Value)
		}
		next++
		checked[seq] = "live instance and held-flow preservation replaces ordered restart operation"
	}
	if next != len(plan) {
		t.Fatal("unconsumed live replacement observations", next, len(plan))
	}
	return checked
}

func checkLiveOrderHeldFlows(t *testing.T, before, after policy.Config) {
	t.Helper()
	table := flows.New(flows.Defaults(), nil)
	defer table.CloseAll()
	apply := func(n uint64, config policy.Config) {
		if _, err := table.Apply(policy.Revision{N: n, Hash: policy.Hash(config), Config: config}); err != nil {
			t.Fatal(err)
		}
	}
	admit := func(port int) {
		ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(fmt.Sprintf("198.18.0.2:%d", port)), Destination: netip.MustParseAddrPort("203.0.113.9:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ticket.Resolve(platform.Owner{AppID: "unassigned"}); err != nil {
			ticket.Close()
			t.Fatal(err)
		}
		ticket.SetCancel(ticket.Close)
	}
	apply(1, before)
	admit(40000)
	held, err := table.Page("")
	if err != nil || len(held.Flows) != 1 || held.Flows[0].Line != "a1" {
		t.Fatal("held-flow precondition", held, err)
	}
	apply(2, after)
	surviving, err := table.Page("")
	if err != nil || !reflect.DeepEqual(surviving.Flows, held.Flows) {
		t.Fatal("live revision changed held flow", surviving, err)
	}
	admit(40001)
	current, err := table.Page("")
	if err != nil || len(current.Flows) != 2 || current.Flows[1].Line != after.Lines[0].ID || current.Flows[1].Revision != 2 {
		t.Fatal("new flow did not follow reordered main", current, err)
	}
}
