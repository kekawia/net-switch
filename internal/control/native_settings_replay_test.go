package control

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
	"github.com/AyoubAchour/net-switch/internal/updates"
)

func replayNativeSettings(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fc *startupFileCursor) map[int]string {
	t.Helper()
	before := e.Snapshot()
	if before.Status != "on" || !c.op.AutostartAllowed || c.autostart != false || c.values["checkForUpdates"] != true || c.offer != nil || len(c.op.Undo.Values()["metrics"].(map[string]any)) != 0 {
		t.Fatal("settings starting condition")
	}
	legacyAdapters := []map[string]any{}
	for _, a := range c.adapters {
		v := map[string]any{}
		for k, x := range a {
			if k != "status" && k != "gateway" && k != "mediaType" {
				v[k] = x
			}
		}
		legacyAdapters = append(legacyAdapters, v)
	}
	metrics := []any{map[string]any{"family": "IPv4", "automatic": true, "metric": float64(25)}}
	var mu sync.Mutex
	autostart, policy := false, any(float64(1))
	release := map[string]any{}
	updateStatus, checks := 200, 0
	type call struct {
		name string
		args map[string]any
	}
	calls := []call{}
	p := c.op.Platform.(*fakePlatform)
	p.mu.Lock()
	p.override = func(name string, args map[string]any) (any, error, bool) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{name, args})
		switch name {
		case "autostart-set":
			autostart = args["on"].(bool)
			return nil, nil, true
		case "autostart":
			return autostart, nil, true
		case "metrics":
			return metrics, nil, true
		case "metrics-set", "metrics-restore":
			return nil, nil, true
		case "policy":
			return policy, nil, true
		case "policy-set":
			policy = args["value"]
			return nil, nil, true
		case "network":
			v := map[string]any{}
			for k, x := range p.network {
				v[k] = x
			}
			v["policy"] = policy
			return v, nil, true
		default:
			return nil, fmt.Errorf("unexpected settings platform call %s", name), true
		}
	}
	p.mu.Unlock()
	c.op.CheckUpdate = func(context.Context) (*updates.Offer, error) {
		mu.Lock()
		defer mu.Unlock()
		checks++
		files.recordOrder("update")
		if updateStatus != 200 {
			return nil, fmt.Errorf("GitHub answered %d", updateStatus)
		}
		return updates.OfferFrom(release, c.op.Version, "x64"), nil
	}
	checked := map[int]string{}
	completion := 58 // the startup's two probe votes have completed
	// Read the already checked original completion boundary, rather than
	// assigning IDs to Go callbacks.
	for _, x := range trace.Entries[:139] {
		if x.Kind == "completion" {
			var v struct{ ID int }
			_ = json.Unmarshal(x.Value, &v)
			completion = v.ID
		}
	}
	type obs struct {
		kind, file string
		value      any
	}
	for _, step := range []struct{ begin, end int }{{139, 159}, {160, 180}, {181, 194}, {195, 216}, {217, 236}, {237, 270}, {271, 276}, {278, 296}, {297, 310}, {311, 326}, {328, 336}, {337, 340}} {
		if step.begin == 278 {
			mu.Lock()
			if checks != 1 || len(release) != 0 {
				t.Fatal("release input precondition")
			}
			if err := json.Unmarshal(trace.Entries[277].Value, &release); err != nil {
				t.Fatal(err)
			}
			mu.Unlock()
			checked[277] = "release input staged for real OfferFrom"
		}
		if step.begin == 328 {
			mu.Lock()
			if updateStatus != 200 || checks != 3 {
				t.Fatal("update failure precondition")
			}
			if err := json.Unmarshal(trace.Entries[327].Value, &updateStatus); err != nil {
				t.Fatal(err)
			}
			if updateStatus != 503 {
				t.Fatal("update status input")
			}
			mu.Unlock()
			checked[327] = "staged failed update response"
		}
		logs := len(files.logs)
		mu.Lock()
		callAt, checkAt := len(calls), checks
		mu.Unlock()
		plan := []obs{}
		add := func(kind string, v any) { plan = append(plan, obs{kind: kind, value: v}) }
		async := func(op string, args []any, value any, undefined bool) {
			add("async-result", map[string]any{"operation": op, "args": args, "ok": true, "value": value, "undefined": undefined})
		}
		log := func(s string) { add("log", map[string]any{"text": s}); async("log.append", []any{s}, nil, true) }
		publish := func(name string) {
			for _, n := range []string{name, name + ".bak"} {
				plan = append(plan, obs{kind: "file-completion", file: n}, obs{kind: "write", file: n}, obs{kind: "file-completion", file: n})
			}
		}
		snapshot := func() { add("state-snapshot", map[string]any{"now": clock.Now().UnixMilli()}) }
		writeSettings := []string{"write:control-journal.json", "write:control-journal.json.bak", "write:settings.json", "write:settings.json.bak"}
		writeUndo := []string{"write:windows-undo.json", "write:windows-undo.json.bak"}
		order := []string{}
		wantCalls := []call{}
		wantLogs := []string{}
		updatesDue := 0
		switch step.begin {
		case 139, 160:
			on := step.begin == 139
			op, word := "platform.enableAutostart", "on"
			args := []any{map[string]any{"root": "/oracle", "nodePath": "/oracle/node", "userDir": "/oracle/data", "machineDir": "/oracle/data"}}
			if !on {
				op, word, args = "platform.disableAutostart", "off", []any{}
			}
			async(op, args, nil, true)
			async("platform.readAutostart", []any{}, on, false)
			note := "starting with Windows is " + word
			log(note)
			wantLogs = []string{note}
			publish("settings.json")
			order = append([]string{"platform:autostart-set", "platform:autostart", "log"}, writeSettings...)
			wantCalls = []call{{"autostart-set", map[string]any{"on": on}}, {"autostart", nil}}
		case 181, 297:
			publish("settings.json")
			order = append(order, writeSettings...)
		case 195:
			async("platform.readMetrics", []any{"Wi-Fi"}, metrics, false)
			publish("windows-undo.json")
			async("platform.applyCableAsMain", []any{legacyAdapters[0], legacyAdapters[1], metrics}, nil, true)
			add("adapter-snapshot", legacyAdapters)
			async("platform.detectAdapters", []any{}, legacyAdapters, false)
			order = append([]string{"platform:metrics"}, writeUndo...)
			order = append(order, "platform:metrics-set", "platform:network")
			wantCalls = []call{{"metrics", map[string]any{"alias": "Wi-Fi"}}, {"metrics-set", map[string]any{"alias": "Wi-Fi", "before": metrics, "metric": float64(100)}}, {"network", nil}}
		case 217:
			async("platform.readMinimizeConnectionsPolicy", []any{}, 1, false)
			publish("windows-undo.json")
			async("platform.allowSimultaneousConnections", []any{}, nil, true)
			async("platform.readMinimizeConnectionsPolicy", []any{}, 0, false)
			order = append([]string{"platform:policy"}, writeUndo...)
			order = append(order, "platform:policy-set", "platform:policy")
			wantCalls = []call{{"policy", nil}, {"policy-set", map[string]any{"value": float64(0)}}, {"policy", nil}}
		case 237:
			async("network.restoreMinimizeConnectionsPolicy", []any{1}, nil, true)
			publish("windows-undo.json")
			async("network.restoreMetrics", []any{"Wi-Fi", metrics}, nil, true)
			publish("windows-undo.json")
			async("platform.readMinimizeConnectionsPolicy", []any{}, 1, false)
			add("adapter-snapshot", legacyAdapters)
			async("platform.detectAdapters", []any{}, legacyAdapters, false)
			order = append([]string{"platform:policy-set"}, writeUndo...)
			order = append(order, "platform:metrics-restore")
			order = append(order, writeUndo...)
			order = append(order, "platform:policy", "platform:network")
			wantCalls = []call{{"policy-set", map[string]any{"value": float64(1)}}, {"metrics-restore", map[string]any{"alias": "Wi-Fi", "metrics": metrics}}, {"policy", nil}, {"network", nil}}
		case 271, 278, 311, 328:
			if step.begin == 278 {
				publish("settings.json")
				order = append(order, writeSettings...)
			}
			mu.Lock()
			body, status := release, updateStatus
			mu.Unlock()
			add("update-reply", map[string]any{"status": status, "body": body})
			order = append(order, "update")
			updatesDue = 1
			if step.begin == 278 {
				note := "Net Switch 0.3.2 is available (this is 0.3.1)"
				log(note)
				wantLogs = []string{note}
				order = append(order, "log")
			}
			if step.begin == 311 {
				publish("settings.json")
				order = append(order, writeSettings...)
			}
			if step.begin == 328 {
				note := "could not check for updates: GitHub answered 503"
				log(note)
				wantLogs = []string{note}
				order = append(order, "log")
			}
		case 337:
		default:
			t.Fatal("unknown settings step")
		}
		snapshot()
		// Assert each command's starting condition, including accumulated Undo.
		switch step.begin {
		case 139:
			if c.autostart != false {
				t.Fatal("autostart already enabled")
			}
		case 160:
			if c.autostart != true {
				t.Fatal("autostart was not enabled")
			}
		case 181:
			if c.values["checkForUpdates"] != true || c.values["probeTargetsCustom"] == true {
				t.Fatal("custom settings precondition")
			}
		case 195:
			if len(c.op.Undo.Values()["metrics"].(map[string]any)) != 0 {
				t.Fatal("metrics already saved")
			}
		case 217:
			if len(c.op.Undo.Values()["policy"].(map[string]any)) != 0 || len(c.op.Undo.Values()["metrics"].(map[string]any)) != 1 {
				t.Fatal("keep-both starting Undo")
			}
		case 237:
			if c.policy != float64(0) || c.op.Undo.Values()["policy"].(map[string]any)["value"] != float64(1) {
				t.Fatal("Undo did not start from changed policy")
			}
		case 271, 278:
			if c.values["checkForUpdates"] != false || c.offer != nil {
				t.Fatal("disabled update starting condition")
			}
		case 297:
			if c.offer == nil || c.offer.Version != "0.3.2" || c.values["skippedUpdate"] != nil {
				t.Fatal("dismiss starting offer")
			}
		case 311:
			if c.values["skippedUpdate"] != "0.3.2" {
				t.Fatal("forced check must clear dismissal")
			}
		}
		replayNativeHTTP(t, c, trace, cmp, step.begin, step.end)
		files.recordOrder("api")
		if err := cmp.Effects(append(order, "api")...); err != nil {
			t.Fatal("settings effects", step.begin, err)
		}
		mu.Lock()
		gotCalls := append([]call{}, calls[callAt:]...)
		checkCount := checks
		mu.Unlock()
		if !reflect.DeepEqual(gotCalls, wantCalls) || checkCount != checkAt+updatesDue {
			t.Fatalf("settings calls %d: %+v / %+v, updates %d/%d", step.begin, gotCalls, wantCalls, checkCount, checkAt+updatesDue)
		}
		if !reflect.DeepEqual(files.logs[logs:], wantLogs) && !(len(files.logs) == logs && len(wantLogs) == 0) {
			t.Fatal("settings diagnostics", step.begin, files.logs[logs:])
		}
		if !reflect.DeepEqual(e.Snapshot(), before) || e.applies != 1 || e.probes.Load() != 2 || len(files.events) != 0 || len(files.removes) != 0 {
			t.Fatal("settings changed running engine")
		}
		checked[step.begin], checked[step.end] = "actual settings/setup/update request", "complete settings/setup/update response"
		next := 0
		for _, x := range trace.Entries[step.begin+1 : step.end] {
			if x.Kind == "completion" {
				completion = checkHealthCompletion(t, trace, x.Seq, completion, checked)
				continue
			}
			if next == len(plan) || plan[next].kind != x.Kind {
				t.Fatalf("settings observation order %d/%s, plan %d", x.Seq, x.Kind, next)
			}
			v := plan[next]
			next++
			if v.file != "" {
				var write struct{ File, Text string }
				if err := json.Unmarshal(x.Value, &write); err != nil {
					t.Fatal(err)
				}
				if startupFileName(write.File) != v.file {
					t.Fatal("settings publication order", x.Seq, write.File, v.file)
				}
				if x.Kind == "write" {
					want := []byte(write.Text)
					if step.begin >= 181 && (v.file == "settings.json" || v.file == "settings.json.bak") {
						m := replayJSON(t, want).(map[string]any)
						m["probeTargetsCustom"] = true
						want = mustStartupJSON(t, m)
					}
					if err := fc.Publication(v.file, want); err != nil {
						t.Fatal(err)
					}
				} else if ok, err := fc.Observe(x); !ok || err != nil {
					t.Fatal("settings file completion", err)
				}
			} else if !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, mustStartupJSON(t, v.value))) {
				t.Fatalf("settings value at %d: %s want %s", x.Seq, x.Value, mustStartupJSON(t, v.value))
			}
			checked[x.Seq] = "exact ordered native settings/setup/update effect"
		}
		if next != len(plan) {
			t.Fatal("unconsumed settings plan", step.begin, next, len(plan))
		}
		if c.values["probeTargetsCustom"] == true {
			for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
				b, err := files.peekFile(filepath.Join("/test", name))
				if err != nil {
					t.Fatal(err)
				}
				var j struct{ Settings map[string]any }
				if err := json.Unmarshal(b, &j); err != nil || j.Settings["probeTargetsCustom"] != true {
					t.Fatal("custom probe marker not durable", err)
				}
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if checks != 4 || autostart || policy != float64(1) || c.values["skippedUpdate"] != nil || c.values["checkForUpdates"] != true || len(c.op.Undo.Values()["metrics"].(map[string]any)) != 0 || len(c.op.Undo.Values()["policy"].(map[string]any)) != 0 {
		t.Fatal("settings final state")
	}
	return checked
}
