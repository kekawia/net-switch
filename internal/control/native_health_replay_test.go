package control

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// The inputs describe the physical world. Only Core changes health, chooses
// probe kinds/operators, counts completed rounds and publishes lane revisions.
func replayNativeHealthSuffix(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fileCursor *startupFileCursor, start int) map[int]string {
	t.Helper()
	if trace.Name != "failoverFailback" && trace.Name != "busyFailedChecks" && trace.Name != "probeFailover" && trace.Name != "lostDefaultRoute" && trace.Name != "ipv6" {
		t.Fatal("health trace not yet implemented", trace.Name)
	}
	checked := map[int]string{}
	origin := clock.Now().UnixMilli()
	for _, id := range []string{"a1", "b2"} {
		l := c.lanes[id]
		if l.health.Up == nil || !*l.health.Up || l.health.ProbeFails != 0 || l.health.ProbePasses != 1 || l.probing || l.probeAt == nil || *l.probeAt != origin {
			t.Fatal("health suffix requires completed healthy startup", id, l.health)
		}
	}
	if len(c.meters) != 0 || len(files.events) != 0 || len(c.evidence) != 0 {
		t.Fatal("health starting observations")
	}
	interfaces := map[string][]map[string]any{
		"Ethernet": {{"family": "IPv4", "address": "192.0.2.1", "internal": false}},
		"Wi-Fi":    {{"family": "IPv4", "address": "192.0.2.2", "internal": false}},
	}
	var routeOverride []any
	probes := map[string]any{}
	var supplied []engine.Connection
	wire := any([]any{})
	reads, polls := 0, 0
	e.fakeEngine.readConnections = func(context.Context) ([]engine.Connection, error) {
		reads++
		files.recordOrder("native:connections")
		return append([]engine.Connection{}, supplied...), nil
	}
	type answer struct {
		request engine.ProbeRequest
		result  engine.ProbeResult
	}
	answers := map[string][]answer{}
	seen := map[string]bool{}
	var mu sync.Mutex
	var probeErr error
	// These baselines are installed before Poll and remain read-only until
	// all operator goroutines join. Even the first completed full check must
	// not publish a partial-round vote.
	roundFails, roundPasses := map[string]int{}, map[string]int{}
	e.probeBegin = func(r engine.ProbeRequest) {
		mu.Lock()
		defer mu.Unlock()
		if r.OperationID == "" || seen[r.OperationID] {
			probeErr = fmt.Errorf("duplicate/empty probe operation: %+v", r)
		}
		seen[r.OperationID] = true
		if err := cmp.Request(r.OperationID); err != nil {
			probeErr = err
		}
	}
	e.fakeEngine.probe = func(r engine.ProbeRequest) engine.ProbeResult {
		v, ok := probes[r.Line]
		if !ok {
			v = float64(18)
		}
		if v == false {
			return engine.ProbeResult{Outcome: engine.LineFailed}
		}
		delay, ok := v.(float64)
		if !ok {
			return engine.ProbeResult{Outcome: engine.Unavailable}
		}
		return engine.ProbeResult{Outcome: engine.OK, Delay: &delay}
	}
	e.probeCheck = func(r engine.ProbeRequest, result engine.ProbeResult) {
		mu.Lock()
		defer mu.Unlock()
		c.mu.Lock()
		h := c.lanes[r.Line].health
		if h.ProbeFails != roundFails[r.Line] || h.ProbePasses != roundPasses[r.Line] {
			probeErr = fmt.Errorf("partial operator round published a vote: %s", r.Line)
		}
		c.mu.Unlock()
		answers[r.Line] = append(answers[r.Line], answer{r, result})
		if err := cmp.Reply(r.OperationID); err != nil {
			probeErr = err
		}
	}
	c.op.ProbeBackground = func(line string, run func()) {
		files.recordOrder("native:probe:" + line)
		run()
		files.recordOrder("native:probe-result:" + line)
	}
	ids := map[string]string{}
	generated := map[string]bool{}
	oldID := c.op.ID
	c.op.ID = func() string {
		mu.Lock()
		defer mu.Unlock()
		id := oldID()
		generated[id] = true
		return id
	}
	last := origin
	ipv6 := trace.Name == "ipv6"
	deferredSources := map[string]int{}
	var ipv6Enabled engine.Policy
	completion := 0
	for _, x := range trace.Entries[:start] {
		if x.Kind == "completion" {
			var v struct{ ID int }
			_ = json.Unmarshal(x.Value, &v)
			completion = v.ID
		}
	}
	for pos := start; pos < len(trace.Entries); {
		x := trace.Entries[pos]
		switch x.Kind {
		case "interfaces":
			if err := json.Unmarshal(x.Value, &interfaces); err != nil {
				t.Fatal(err)
			}
			checked[pos] = "physical interface input staged without a health vote"
			pos++
		case "routes":
			if err := json.Unmarshal(x.Value, &routeOverride); err != nil {
				t.Fatal(err)
			}
			checked[pos] = "route input staged until next sampling deadline"
			pos++
		case "probes":
			if err := json.Unmarshal(x.Value, &probes); err != nil {
				t.Fatal(err)
			}
			checked[pos] = "physical probe answers staged without a vote"
			pos++
		case "connections":
			if err := json.Unmarshal(x.Value, &supplied); err != nil {
				t.Fatal(err)
			}
			wire = replayJSON(t, x.Value)
			for i := range supplied {
				if supplied[i].ID != "busy" || len(supplied) != 1 {
					t.Fatal("unexpected health flow input")
				}
				supplied[i].ID = e.Snapshot().Instance + ":1"
			}
			checked[pos] = "instance-scoped physical flow snapshot staged"
			pos++
		case "http":
			end := pos + 1
			for end < len(trace.Entries) && trace.Entries[end].Kind != "api" {
				end++
			}
			if end == len(trace.Entries) {
				t.Fatal("missing health API response")
			}
			for i := range cmp.entries {
				if cmp.entries[i].Seq < pos {
					continue
				}
				b, err := rewriteTraceStrings(cmp.entries[i].Value, func(s string) string {
					if id := ids[s]; id != "" {
						return id
					}
					return s
				})
				if err != nil {
					t.Fatal(err)
				}
				cmp.entries[i].Value = b
			}
			at := clock.Now()
			guard := replayStartupHTTP(t, c, x, trace.Entries[end], cmp)
			checked[pos], checked[end] = guard, guard
			for i := pos + 1; i < end; i++ {
				entry := trace.Entries[i]
				if entry.Kind == "state-snapshot" {
					var v struct{ Now int64 }
					_ = json.Unmarshal(entry.Value, &v)
					if v.Now != at.UnixMilli() || clock.Now() != at {
						t.Fatal("snapshot boundary")
					}
					checked[i] = "actual response constructed at snapshot time"
				} else if entry.Kind == "completion" {
					completion = checkHealthCompletion(t, trace, i, completion, checked)
				} else {
					t.Fatal("unexpected response boundary", entry)
				}
			}
			pos = end + 1
		case "clock-tick":
			var tick struct{ Now int64 }
			_ = json.Unmarshal(x.Value, &tick)
			if tick.Now != last+1000 {
				t.Fatal("health poll deadline", tick.Now, last)
			}
			clock.at = time.UnixMilli(tick.Now).UTC()
			last = tick.Now
			polls++
			end := pos + 1
			for end < len(trace.Entries) {
				entry := trace.Entries[end]
				if entry.Kind == "clock-tick" {
					var next struct{ Now int64 }
					_ = json.Unmarshal(entry.Value, &next)
					if next.Now != tick.Now {
						break
					}
				} else if entry.Direction == "input" && (entry.Kind == "http" || entry.Kind == "interfaces" || entry.Kind == "routes" || entry.Kind == "probes" || entry.Kind == "connections") {
					break
				}
				end++
			}
			elapsed := tick.Now - origin
			logsAt, eventsAt, effectAt := len(files.logs), len(files.events), len(files.order)
			before := e.Snapshot()
			want := twoLineNativeConfig(map[string]string{})
			if ipv6 {
				want.IPv6 = elapsed >= 31000 && elapsed < 62000
			}
			down := trace.Name == "failoverFailback" && elapsed >= 3000 && elapsed < 5000 || trace.Name == "probeFailover" && elapsed >= 26000 && elapsed < 41000 || trace.Name == "lostDefaultRoute" && elapsed >= 11000 && elapsed < 16000
			if down {
				want.Lanes["a1"] = "b2"
			}
			e.want = want
			if ipv6 && elapsed%60000 == 0 {
				if err := c.SaveUsage(); err != nil {
					t.Fatal(err)
				}
			}
			// A worker network input supplies addresses every poll. Health itself
			// spaces route votes; the five-second discovery callback is separate.
			p := c.op.Platform.(*fakePlatform)
			adapters := []any{}
			routes := []any{}
			for _, raw := range p.network["adapters"].([]any) {
				a := map[string]any{}
				for k, v := range raw.(map[string]any) {
					a[k] = v
				}
				ips := []any{}
				hasIPv6 := false
				for _, addr := range interfaces[a["alias"].(string)] {
					if addr["family"] == "IPv6" && addr["internal"] == false {
						hasIPv6 = true
					}
					if addr["family"] == "IPv4" && addr["internal"] == false {
						ips = append(ips, addr["address"])
						routes = append(routes, map[string]any{"interfaceAddress": addr["address"]})
					}
				}
				a["ipv4s"] = ips
				if ipv6 {
					a["ipv6"] = hasIPv6
				}
				adapters = append(adapters, a)
			}
			if routeOverride != nil {
				routes = routeOverride
			}
			p.network = map[string]any{"adapters": adapters, "defaultRoutes": routes, "policy": c.policy, "readAt": float64(tick.Now)}
			if err := c.RefreshAdapters(context.Background()); err != nil {
				t.Fatal(err)
			}
			beforeRoutes := map[string]*int64{}
			doubt := map[string]bool{}
			operators := map[string]int{}
			fails, passes := map[string]int{}, map[string]int{}
			for _, id := range []string{"a1", "b2"} {
				l := c.lanes[id]
				beforeRoutes[id] = l.routeReadAt
				doubt[id] = l.health.InDoubt()
				operators[id] = l.operator
				fails[id] = l.health.ProbeFails
				passes[id] = l.health.ProbePasses
			}
			answers = map[string][]answer{}
			for _, id := range []string{"a1", "b2"} {
				roundFails[id], roundPasses[id] = fails[id], passes[id]
			}
			if trace.Name == "failoverFailback" && elapsed == 4000 {
				// Address recovery resets the history before dispatching checks.
				roundFails["a1"], roundPasses["a1"] = 0, 0
			}
			files.recordOrder("native:poll")
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.guardError != nil || probeErr != nil {
				t.Fatal("health native boundary", e.guardError, probeErr)
			}
			if reads != polls {
				t.Fatal("poll duplicated/missing connection read", reads, polls)
			}
			if trace.Name == "lostDefaultRoute" {
				misses := 0
				if elapsed >= 5000 && elapsed < 10000 {
					misses = 1
				}
				if elapsed >= 10000 && elapsed < 15000 {
					misses = 2
				}
				for _, id := range []string{"a1", "b2"} {
					l := c.lanes[id]
					wantMisses := 0
					if id == "a1" {
						wantMisses = misses
					}
					if l.health.RouteMisses != wantMisses || l.routeReadAt == nil || *l.routeReadAt != origin+(elapsed/5000)*5000 {
						t.Fatal("route observation grace/cadence", elapsed, id, l.health.RouteMisses, l.routeReadAt)
					}
				}
			}
			changed := before.StartedWith.Lanes["a1"] != want.Lanes["a1"]
			ipv6Changed := ipv6 && before.Policy.IPv6 != want.IPv6
			if (e.Snapshot().AppliedRevision != before.AppliedRevision) != (changed || ipv6Changed) {
				t.Fatal("unexpected/missing health revision")
			}
			if ipv6 {
				if e.Snapshot().Instance != before.Instance || e.Snapshot().Status != "on" || e.Snapshot().Policy.IPv6 != want.IPv6 {
					t.Fatal("IPv6 live instance/loaded policy", elapsed)
				}
				deadline := origin + 1000
				if elapsed >= 32000 {
					deadline = origin + 32000
				}
				if elapsed != 31000 && elapsed != 62000 && (c.ipv6Since == nil || *c.ipv6Since != deadline) {
					t.Fatal("stable IPv6 observation interval", elapsed, c.ipv6Since)
				}
				if elapsed == 31000 {
					ipv6Enabled = e.Snapshot().Policy
				}
				if elapsed == 62000 {
					checkNativeIPv6Closure(t, ipv6Enabled, e.Snapshot().Policy)
				}
				for _, v6 := range []bool{false, true} {
					d, err := e.active.Decide(platform.Owner{AppID: "unassigned"}, 40000, v6, 1)
					if v6 && !want.IPv6 {
						if err != policy.ErrIPv6 {
							t.Fatal("IPv6 permission result", elapsed, err)
						}
					} else if err != nil || d.Line != "a1" {
						t.Fatal("IPv6 native decision", elapsed, d, err)
					}
				}
			}
			for _, id := range []string{"a1", "b2"} {
				l := c.lanes[id]
				if l.health.Up == nil || *l.health.Up != (id == "b2" || !down) {
					t.Fatal("health transition timing", elapsed, id, l.health)
				}
				if l.probing {
					t.Fatal("unfinished round")
				}
				probeDue := elapsed%15000 == 0
				if trace.Name == "failoverFailback" {
					probeDue = id == "a1" && elapsed == 4000
				}
				if trace.Name == "probeFailover" && id == "a1" {
					probeDue = elapsed >= 15000 && elapsed <= 40000 && elapsed%5000 == 0
				}
				if (len(answers[id]) != 0) != probeDue {
					t.Fatal("physical probe deadline", id, elapsed, answers[id])
				}
				if len(answers[id]) == 0 {
					continue
				}
				// Recovery after an address return resets the probe history.
				if l.health.RecoveredAt != nil && *l.health.RecoveredAt == tick.Now {
					doubt[id] = true
					fails[id] = 0
					passes[id] = 0
				}
				failed := probes[id] == false
				count := 1
				if doubt[id] {
					count = 2
				} else if failed {
					count = 3
				}
				if len(answers[id]) != count {
					t.Fatal("complete native operator round", id, elapsed, len(answers[id]), count)
				}
				full := map[string]bool{}
				quick := 0
				for _, a := range answers[id] {
					kind := "full"
					if a.request.Quick {
						kind = "quick"
						quick++
					}
					if a.request.Line != id || a.request.Index != 0 || a.request.Custom || a.result.Instance != e.Snapshot().Instance || a.result.Kind != kind {
						t.Fatal("physical probe fence", a)
					}
					delay := float64(18)
					if value, ok := probes[id].(float64); ok {
						delay = value
					}
					if !generated[a.request.OperationID] || failed && a.result.Delay != nil || !failed && (a.result.Delay == nil || *a.result.Delay != delay) {
						t.Fatal("physical operation identity/delay", a)
					}
					if a.request.Quick {
						if doubt[id] {
							t.Fatal("quick recovery")
						}
						if a.request.Target != []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}[operators[id]%3] {
							t.Fatal("quick operator rotation", a)
						}
					} else {
						if full[a.request.Target] {
							t.Fatal("duplicate full operator")
						}
						full[a.request.Target] = true
					}
					if failed != (a.result.Outcome == engine.LineFailed) {
						t.Fatal("probe input outcome", a)
					}
				}
				if doubt[id] && quick != 0 || !doubt[id] && quick != 1 {
					t.Fatal("probe kind count")
				}
				wantFull := map[string]bool{}
				if doubt[id] || failed {
					op := operators[id] % 3
					if !doubt[id] {
						op = (op + 1) % 3
					}
					targets := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
					wantFull[targets[op]], wantFull[targets[(op+1)%3]] = true, true
				}
				if !reflect.DeepEqual(full, wantFull) {
					t.Fatal("rotating full operators", full, operators[id])
				}
				busy := c.tracker.LineRate(id).Down >= 16*1024 || c.tracker.LineRate(id).Up >= 16*1024
				if busy != (trace.Name == "busyFailedChecks" && id == "a1") {
					t.Fatal("busy suppression starting traffic", id, c.tracker.LineRate(id))
				}
				if failed && busy {
					if l.health.ProbeFails != fails[id] || l.health.ProbePasses != passes[id] {
						t.Fatal("busy round counted")
					}
				} else if failed {
					if l.health.ProbeFails != fails[id]+1 || l.health.ProbePasses != 0 {
						t.Fatal("failed round counted more/less than once")
					}
				} else if l.health.ProbeFails != 0 || l.health.ProbePasses != passes[id]+1 {
					t.Fatal("passed round counted more/less than once")
				}
			}
			for _, owner := range []string{"", `c:\apps\firefox.exe`} {
				d, err := e.active.Decide(platform.Owner{AppID: owner}, 40000, false, 1)
				if err != nil || d.Line != want.Lanes["a1"] {
					t.Fatal("native failover decision", d, err)
				}
			}
			order := []string{"platform:network", "native:poll"}
			if ipv6 && elapsed%60000 == 0 {
				order = append([]string{"write:usage.json"}, order...)
			}
			if ipv6Changed {
				order = append(order, "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack")
			}
			if changed {
				order = append(order, "log", "event", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "lane-log")
			}
			order = append(order, "native:connections")
			if trace.Name == "busyFailedChecks" && polls == 2 {
				order = append(order, "platform:app-info")
			}
			probeLogs := len(files.logs) - logsAt
			if changed {
				probeLogs -= 2
			}
			for _, id := range []string{"a1", "b2"} {
				if len(answers[id]) == 0 {
					continue
				}
				order = append(order, "native:probe:"+id)
				if id == "a1" && probeLogs > 0 {
					order = append(order, "log")
				}
				order = append(order, "native:probe-result:"+id)
			}
			if err := cmp.Effects(order...); err != nil {
				t.Fatal("health effect order", elapsed, err, files.order[effectAt:])
			}
			if ipv6Changed {
				ruleStart, ruleEnd, retiredStart, retiredEnd, configSeq, pidSeq := 571, 591, 545, 634, 593, 599
				note := "every line has IPv6 now: routing restarts to carry it too"
				if elapsed == 62000 {
					ruleStart, ruleEnd, retiredStart, retiredEnd, configSeq, pidSeq = 1087, 1107, 1061, 1150, 1109, 1115
					note = "a line lost IPv6: routing restarts to keep apps on IPv4"
				}
				proof, err := fileCursor.CheckRevision(trace.Entries[ruleStart:ruleEnd], twoLineRevisionFiles(), cmp, effectAt)
				if err != nil {
					t.Fatal(err)
				}
				for seq, guard := range proof {
					checked[seq] = guard
				}
				part := trace
				part.Entries = trace.Entries[:retiredEnd]
				checkNativeLiveEntries(t, part, clock, fileCursor, retiredStart-1, configSeq, pidSeq, want, checked, nativeLiveRestartPlan(t, clock, "ipv6", note))
			} else if _, err := fileCursor.CheckRevision(trace.Entries[pos+1:end], nil, cmp, effectAt); err != nil {
				t.Fatal(err)
			}
			// Project completed native operations into the historical scheduling
			// order. The values below come only from those native operations or
			// the staged physical inputs, never from expected output entries.
			counterparts := &startupCounterparts{cmp: cmp}
			type observation struct {
				kind  string
				value any
			}
			projected := []observation{}
			find := func(key string) int {
				if ipv6 && (key == "native:probe:a1" || key == "native:probe:b2" || key == "native:probe-result:a1" || key == "native:probe-result:b2") {
					if source, ok := deferredSources[key]; ok {
						return source
					}
				}
				for i := effectAt; i < len(files.order); i++ {
					if files.order[i] == key {
						return i
					}
				}
				return -1
			}
			projectProbe := map[string]bool{}
			for _, id := range []string{"a1", "b2"} {
				projectProbe[id] = len(answers[id]) > 0
				if ipv6 {
					for i := effectAt; i < len(files.order); i++ {
						if files.order[i] == "native:probe:"+id || files.order[i] == "native:probe-result:"+id {
							if _, exists := deferredSources[files.order[i]]; exists {
								t.Fatal("unconsumed native IPv6 probe")
							}
							deferredSources[files.order[i]] = i
						}
					}
					projectProbe[id] = elapsed <= 31000 && elapsed%15000 == 0 || elapsed > 31000 && (elapsed-31000)%15000 == 0
				}
			}
			add := func(kind, id string, value any, source string) {
				projected = append(projected, observation{kind, value})
				counterparts.want = append(counterparts.want, startupCounterpart{kind, id, find(source)})
			}
			async := func(op string, value any, source string) {
				add("async-result", op, map[string]any{"operation": op, "args": []any{}, "ok": true, "value": value, "undefined": false}, source)
			}
			log := func(index int, source string) { add("log", "", map[string]any{"text": files.logs[index]}, source) }
			appendLog := func(index int, source string) {
				add("async-result", "log.append", map[string]any{"operation": "log.append", "args": []any{files.logs[index]}, "ok": true, "value": nil, "undefined": true}, source)
			}
			if elapsed%5000 == 0 {
				// Adapter snapshots aren't part of the counterpart cursor; they
				// still get an exact comparison with the production scan result.
				legacyAdapters := []map[string]any{}
				for _, a := range c.adapters {
					item := map[string]any{}
					for k, v := range a {
						if k != "status" && k != "gateway" && k != "mediaType" && k != "ipv6" {
							item[k] = v
						}
					}
					legacyAdapters = append(legacyAdapters, item)
				}
				projected = append(projected, observation{"adapter-snapshot", legacyAdapters})
				async("platform.detectAdapters", legacyAdapters, "platform:network")
				if ipv6 && elapsed%60000 == 0 {
					async("platform.readMinimizeConnectionsPolicy", c.policy, "platform:network")
				}
			}
			if changed {
				if len(files.events) != eventsAt+1 {
					t.Fatal("missing health transition event")
				}
				log(logsAt, "log")
				ev := files.events[eventsAt].(map[string]any)
				add("event", ev["kind"].(string)+" a1", ev, "event")
			} else if len(files.events) != eventsAt {
				t.Fatal("spurious health event")
			}
			probeRequest := func(id string) {
				route := "/proxies/line-" + id + "/delay"
				add("engine", "GET "+route, map[string]any{"method": "GET", "route": route}, "native:probe:"+id)
				delay, ok := probes[id]
				if !ok {
					delay = float64(18)
				}
				status := 200
				if delay == false {
					status = 503
				}
				add("probe-result", route, map[string]any{"route": route, "status": status, "body": map[string]any{"delay": delay}}, "native:probe-result:"+id)
			}
			for _, id := range []string{"a1", "b2"} {
				if len(answers[id]) > 0 && doubt[id] {
					probeRequest(id)
					probeRequest(id)
				}
			}
			for _, alias := range []string{"Ethernet", "Wi-Fi"} {
				if _, ok := c.meters[alias]; ok {
					t.Fatal("invented physical counters")
				}
				add("counter-sample", alias, map[string]any{"alias": alias, "value": nil}, "native:poll")
			}
			if changed {
				appendLog(logsAt, "log")
			}
			for _, id := range []string{"a1", "b2"} {
				routeDue := c.lanes[id].routeReadAt != beforeRoutes[id]
				if ipv6 {
					if c.lanes[id].routeReadAt == nil || *c.lanes[id].routeReadAt != origin+(elapsed/5000)*5000 {
						t.Fatal("retained five-second route cadence", elapsed, id)
					}
					if routeDue {
						if _, exists := deferredSources["route:"+id]; exists {
							t.Fatal("unconsumed native IPv6 route read")
						}
						deferredSources["route:"+id] = find("platform:network")
					}
					routeDue = elapsed <= 31000 && elapsed%5000 == 0 || elapsed > 31000 && (elapsed-31000)%5000 == 0
				}
				if routeDue {
					async("platform.readDefaultRoutes", routes, "platform:network")
					if ipv6 {
						source, ok := deferredSources["route:"+id]
						if !ok {
							t.Fatal("missing retained route observation", elapsed, id)
						}
						counterparts.want[len(counterparts.want)-1].source = source
						delete(deferredSources, "route:"+id)
					}
				}
			}
			for _, id := range []string{"a1", "b2"} {
				if projectProbe[id] && !doubt[id] {
					probeRequest(id)
				}
			}
			for _, id := range []string{"a1", "b2"} {
				if len(answers[id]) > 0 && !doubt[id] && probes[id] == false {
					probeRequest(id)
				}
			}
			for _, id := range []string{"a1", "b2"} {
				if !projectProbe[id] || probes[id] == false {
					continue
				}
				n := 1
				if doubt[id] {
					n = 2
				}
				delay, ok := probes[id]
				if !ok {
					delay = float64(18)
				}
				for i := 0; i < n; i++ {
					async("engine./proxies/line-"+id+"/delay.json", map[string]any{"delay": delay}, "native:probe-result:"+id)
				}
			}
			if changed {
				route := "/proxies/lane-a1"
				add("engine", "PUT "+route, map[string]any{"route": route, "method": "PUT", "body": map[string]any{"name": "line-" + want.Lanes["a1"]}}, "native:ack")
				add("engine-reply", route, map[string]any{"route": route, "status": 200, "body": map[string]any{}}, "native:ack")
				log(logsAt+1, "lane-log")
				appendLog(logsAt+1, "lane-log")
			}
			add("engine", "GET /connections", map[string]any{"method": "GET", "route": "/connections"}, "native:connections")
			add("engine-reply", "/connections", map[string]any{"route": "/connections", "status": 200, "body": map[string]any{"connections": wire}}, "native:connections")
			if probeLogs > 0 {
				if probeLogs != 1 {
					t.Fatal("unexpected probe diagnostics")
				}
				log(len(files.logs)-1, "log")
				appendLog(len(files.logs)-1, "log")
			}
			if trace.Name == "lostDefaultRoute" {
				for _, id := range []string{"a1", "b2"} {
					if len(answers[id]) > 0 {
						add("probe-vote", id, map[string]any{"line": id, "result": true, "at": tick.Now}, "native:probe-result:"+id)
					}
				}
			}
			async("engine./connections.json", map[string]any{"connections": wire}, "native:connections")
			next := 0
			for seq := pos; seq < end; seq++ {
				entry := trace.Entries[seq]
				if entry.Kind == "clock-tick" {
					checked[seq] = "completed native poll at exact deadline"
					continue
				}
				if entry.Kind == "completion" {
					completion = checkHealthCompletion(t, trace, seq, completion, checked)
					continue
				}
				if ipv6 && checked[seq] != "" {
					continue
				}
				if ipv6 && entry.Kind == "file-completion" {
					matched, err := fileCursor.Observe(entry)
					if !matched || err != nil {
						t.Fatal("IPv6 usage completion", seq, err)
					}
					checked[seq] = "distinct native minute usage publication"
					continue
				}
				if ipv6 && entry.Kind == "write" {
					var value struct{ File, Text string }
					_ = json.Unmarshal(entry.Value, &value)
					if value.File != "/oracle/data/usage.json" {
						t.Fatal("unexpected IPv6 publication", seq)
					}
					if err := fileCursor.Publication("usage.json", []byte(value.Text)); err != nil {
						t.Fatal(err)
					}
					checked[seq] = "distinct native minute usage publication"
					continue
				}
				if next >= len(projected) || projected[next].kind != entry.Kind {
					t.Fatalf("health observation order at %d: %s, next %d/%d %+v", seq, entry.Kind, next, len(projected), projected)
				}
				actual := projected[next].value
				wantValue := replayJSON(t, entry.Value)
				if entry.Kind == "event" {
					old := wantValue.(map[string]any)["id"].(string)
					id := actual.(map[string]any)["id"].(string)
					if ids[old] != "" || !generated[id] {
						t.Fatal("event identity bijection")
					}
					for _, v := range ids {
						if v == id {
							t.Fatal("event identity reused")
						}
					}
					ids[old] = id
					wantValue.(map[string]any)["id"] = id
				}
				if !reflect.DeepEqual(wantValue, replayJSON(t, mustStartupJSON(t, actual))) {
					t.Fatalf("health value at %d %s: got %s want %s", seq, entry.Kind, mustStartupJSON(t, actual), mustStartupJSON(t, wantValue))
				}
				if err := counterparts.Observe(entry); err != nil {
					t.Fatal(err)
				}
				checked[seq] = "exact ordered native health observation"
				next++
			}
			if next != len(projected) {
				t.Fatal("unconsumed health observations", projected[next:])
			}
			if err := counterparts.Finish(); err != nil {
				t.Fatal(err)
			}
			if ipv6 {
				for _, id := range []string{"a1", "b2"} {
					if projectProbe[id] {
						delete(deferredSources, "native:probe:"+id)
						delete(deferredSources, "native:probe-result:"+id)
					}
				}
			}
			pos = end
		default:
			t.Fatal("unsupported health input", x)
		}
	}
	if err := fileCursor.skipNative(); err != nil {
		t.Fatal(err)
	}
	if ipv6 && (len(deferredSources) != 0 || polls != 62 || reads != 62 || e.applies != 3 || e.probes.Load() != 10) {
		t.Fatal("IPv6 interval exhaustion", deferredSources, polls, reads, e.applies, e.probes.Load())
	}
	return checked
}

func checkHealthCompletion(t *testing.T, trace replayledger.Trace, seq, previous int, checked map[int]string) int {
	t.Helper()
	var v struct {
		ID   int
		Kind string
	}
	if err := json.Unmarshal(trace.Entries[seq].Value, &v); err != nil {
		t.Fatal(err)
	}
	if seq == 0 || v.ID != previous+1 || v.Kind != trace.Entries[seq-1].Kind || checked[seq-1] == "" {
		t.Fatal("unproved health completion", seq, v, previous)
	}
	checked[seq] = checked[seq-1] + " completed"
	return v.ID
}
