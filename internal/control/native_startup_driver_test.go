package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// A guard may cover several representations of the SAME completed operation:
// e.g. a rule write, its callback, and its completion all become one complete
// acknowledged revision. Markers never manufacture an operation or a result.
func replayNativeStartup(t *testing.T, name string) {
	t.Helper()
	mapping, err := replayledger.DefaultMapping()
	if err != nil {
		t.Fatal(err)
	}
	traces, err := replayledger.Load("../..", mapping)
	if err != nil {
		t.Fatal(err)
	}
	report, err := replayledger.Build(mapping, traces)
	if err != nil {
		t.Fatal(err)
	}
	var trace replayledger.Trace
	var hash string
	for h, candidate := range traces {
		if candidate.Name == name {
			trace, hash = candidate, h
		}
	}
	if hash == "" {
		t.Fatal("missing hash-verified startup fixture", name)
	}
	var rows []replayledger.Row
	for _, row := range report.Rows {
		if row.Hash == hash && row.Assertion == "internal/control/native_startup_replay_test.go#"+t.Name() {
			rows = append(rows, row)
		}
	}
	var initial struct{ Settings json.RawMessage }
	if err := json.Unmarshal(trace.Entries[0].Value, &initial); err != nil {
		t.Fatal(err)
	}
	files := &memoryFiles{data: map[string][]byte{filepath.Join("/test", "settings.json"): initial.Settings}, observeAllWrites: true, observeReads: true}
	clock := &fakeClock{at: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), afterImmediate: true}
	cmp := &nativeTraceComparator{effects: &files.order}
	for _, entry := range trace.Entries {
		if entry.Kind != "http" && entry.Kind != "api" {
			continue
		}
		value := entry.Value
		if entry.Kind == "api" {
			var response map[string]any
			if err := json.Unmarshal(value, &response); err != nil {
				t.Fatal(err)
			}
			operatorStateExpectation(response["body"].(map[string]any), false)
			value = mustStartupJSON(t, response)
		}
		cmp.entries = append(cmp.entries, traceEntry{Seq: entry.Seq, Kind: entry.Kind, Direction: entry.Direction, Value: value})
	}
	check := func(guard string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s guard: %v", guard, err)
		}
	}
	equal := func(guard string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s guard: got %#v want %#v", guard, got, want)
		}
	}
	// Assert starting absence, before constructing Store or Core.
	for _, file := range []string{"windows-undo.json", "usage.json", "control-journal.json", "engine.pid"} {
		if _, exists := files.data[filepath.Join("/test", file)]; exists {
			t.Fatal("initial absence guard", file)
		}
	}
	c, base, _, _ := testCoreWithFilesMode(t, files, clock, true)
	base.ackPoint = 1
	e := &nativeStartupEngine{fakeEngine: base, files: files, want: twoLineNativeConfig(map[string]string{`c:\discord\app-*\discord.exe`: "b2"})}
	c.op.Engine = e
	check("store construction order", cmp.Effects("read:settings.json:ok", "read:control-journal.json:missing", "read:windows-undo.json:missing", "log", "log", "read:usage.json:missing", "read:usage.recovery.json:missing"))
	if len(files.reads) == 0 || !bytes.Equal(files.reads[0].Bytes, initial.Settings) {
		t.Fatal("ordered settings read guard")
	}
	loaded := c.op.Settings.RawValues()
	var saved map[string]json.RawMessage
	check("initial settings", json.Unmarshal(initial.Settings, &saved))
	for key, value := range saved {
		a, _ := orderedTraceJSON(value)
		b, _ := orderedTraceJSON(loaded[key])
		equal("saved setting "+key, b, a)
	}
	// Service mode starts at sign-in, after durable intent publication.
	if c.WantsRouting() {
		t.Fatal("initial service intent must be off")
	}
	check("sign-in", c.SignIn(context.Background()))
	check("intent durability", cmp.Effects("write:control-journal.json", "write:control-journal.json.bak"))
	if !c.WantsRouting() {
		t.Fatal("sign-in publication guard")
	}

	// Feed recorded platform values through production platform-call consumers.
	var adapters []map[string]any
	var routes []map[string]any
	var policyValue any
	for _, entry := range trace.Entries {
		if entry.Kind == "adapter-snapshot" && adapters == nil {
			check("adapter input", json.Unmarshal(entry.Value, &adapters))
		}
		if entry.Kind == "async-result" {
			var v struct {
				Operation string
				Value     json.RawMessage
			}
			check("platform input", json.Unmarshal(entry.Value, &v))
			if v.Operation == "platform.readDefaultRoutes" && routes == nil {
				check("routes input", json.Unmarshal(v.Value, &routes))
			}
			if v.Operation == "platform.readMinimizeConnectionsPolicy" {
				check("policy input", json.Unmarshal(v.Value, &policyValue))
			}
		}
	}
	workerAdapters := []any{}
	for _, a := range adapters {
		copy := map[string]any{}
		for k, v := range a {
			copy[k] = v
		}
		copy["status"], copy["gateway"] = "Up", "192.0.2.254"
		if copy["kind"] == "wifi" {
			copy["mediaType"] = "wireless"
		}
		workerAdapters = append(workerAdapters, copy)
	}
	workerRoutes := []any{}
	for _, r := range routes {
		workerRoutes = append(workerRoutes, r)
	}
	p := c.op.Platform.(*fakePlatform)
	p.network = map[string]any{"adapters": workerAdapters, "defaultRoutes": workerRoutes, "policy": policyValue, "readAt": float64(clock.Now().UnixMilli())}
	c.adapters, c.routes, c.policy, c.elevated = nil, nil, nil, false
	c.CheckElevation(context.Background())
	if !c.elevated {
		t.Fatal("elevation result guard")
	}
	check("adapter scan", c.RefreshAdapters(context.Background()))
	equal("platform operations", p.calls, []string{"elevated", "network"})
	equal("route result", c.routes, routes)
	equal("policy result", c.policy, policyValue)
	check("platform effects", cmp.Effects())
	console, err := c.PublishSession(47821, strings.Repeat("01", 24), 123)
	check("session publish", err)
	files.recordOrder("console")
	check("session order", cmp.Effects("write:server.json", "log", "console"))
	if c.initialSampled {
		t.Fatal("poll precondition: already sampled")
	}
	check("initial physical sample", c.Poll(context.Background()))
	if !c.initialSampled || len(c.meters) != 0 {
		t.Fatal("null physical counters guard")
	}
	check("poll effects", cmp.Effects())

	// Each mutation must see matching durable desired/settings before it runs.
	e.check = func(r engine.Revision) error {
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			var journal struct {
				Desired  engine.Revision
				Wanted   bool
				Settings map[string]json.RawMessage
			}
			if err := json.Unmarshal(files.data[filepath.Join("/test", name)], &journal); err != nil {
				return err
			}
			if !journal.Wanted || !reflect.DeepEqual(journal.Desired, r) {
				return fmt.Errorf("%s lacks desired revision/intent", name)
			}
			for k, want := range saved {
				a, _ := orderedTraceJSON(want)
				b, _ := orderedTraceJSON(journal.Settings[k])
				if !reflect.DeepEqual(a, b) {
					return fmt.Errorf("journal setting %s differs", k)
				}
			}
		}
		if !bytes.Equal(files.data[filepath.Join("/test", "settings.json")], initial.Settings) {
			return fmt.Errorf("startup changed saved settings")
		}
		return nil
	}
	base.beforeStart = func() { check("initial usage save", c.SaveUsage()) }
	type answer struct {
		request engine.ProbeRequest
		result  engine.ProbeResult
	}
	var probeMu sync.Mutex
	var probeErr error
	answers := map[string][]answer{}
	c.op.ProbeBackground = func(line string, run func()) {
		check("probe group", cmp.Begin("probe:"+line))
		files.recordOrder("native:probe:" + line)
		run()
		files.recordOrder("native:probe-result:" + line)
		check("probe group", cmp.End("probe:"+line))
	}
	e.probeBegin = func(request engine.ProbeRequest) {
		probeMu.Lock()
		defer probeMu.Unlock()
		if err := cmp.Request(request.OperationID); err != nil {
			probeErr = err
		}
	}
	e.probeCheck = func(request engine.ProbeRequest, result engine.ProbeResult) {
		probeMu.Lock()
		defer probeMu.Unlock()
		answers[request.Line] = append(answers[request.Line], answer{request, result})
		if err := cmp.Reply(request.OperationID); err != nil {
			probeErr = err
		}
	}
	if base.Snapshot().Status != "off" || e.active != nil {
		t.Fatal("startup off precondition")
	}
	check("startup revision group", cmp.Begin("startup"))
	check("start request", cmp.Request("start"))
	check("native start", c.Start(context.Background()))
	check("start result", cmp.Reply("start"))
	check("native boundary", e.guardError)
	check("probe request/result bijection", probeErr)
	check("startup revision group", cmp.End("startup"))
	// Diagnostic logs, usage and native transactions share the same stream.
	check("startup order", cmp.Effects("write:control-journal.json", "write:control-journal.json.bak", "native:desired", "log", "native:start", "write:usage.json", "native:apply", "native:ack", "native:started", "log", "lane-log", "lane-log", "native:probe:a1", "native:probe-result:a1", "native:probe:b2", "native:probe-result:b2"))
	if e.active == nil || e.applies != 1 || len(files.syncs) == 0 {
		t.Fatal("complete durable revision guard")
	}
	// The already-applied path publishes once, without issuing another apply
	// or repeating its lane diagnostics on every later supervisor pass.
	check("idempotent policy publication", c.ApplyPolicy(context.Background()))
	check("no repeated publication effects", cmp.Effects())
	for _, owner := range []string{`C:\Discord\app-1.0.9\Discord.exe`, `C:\Discord\app-1.0.10\Discord.exe`, `C:\Discord\app-2.0.0\Discord.exe`} {
		d, err := e.active.Decide(platform.Owner{AppID: apppath.Normalize(owner, apppath.Windows)}, 40000, false, 1)
		if err != nil || d.Line != "b2" || d.Revision != base.Snapshot().AppliedRevision {
			t.Fatal("complete pin replacement guard", d, err)
		}
	}
	// No stale compiled rule/PID/log artifacts survive in the native boundary.
	for path := range files.data {
		if strings.Contains(filepath.Base(path), "apps-") || strings.Contains(filepath.Base(path), "share-") || strings.Contains(filepath.Base(path), "cut-") || strings.HasPrefix(filepath.Base(path), "engine") {
			t.Fatal("obsolete artifact guard", path)
		}
	}
	seenOps := map[string]bool{}
	for _, line := range []string{"a1", "b2"} {
		if len(answers[line]) != 1 {
			t.Fatal("healthy startup needs one successful quick probe", line, answers[line])
		}
		targets := map[string]bool{}
		for _, a := range answers[line] {
			if a.request.OperationID == "" || seenOps[a.request.OperationID] || a.request.Custom || a.request.Index != 0 || a.result.Instance != base.Snapshot().Instance || a.result.Outcome != engine.OK || a.result.Delay == nil || *a.result.Delay != 18 {
				t.Fatal("physical probe fence/result guard", a)
			}
			seenOps[a.request.OperationID] = true
			if !a.request.Quick || targets[a.request.Target] || a.request.Target != "1.1.1.1:443" {
				t.Fatal("physical startup operator guard", a)
			}
			targets[a.request.Target] = true
			kind := "full"
			if a.request.Quick {
				kind = "quick"
			}
			if a.result.Kind != kind {
				t.Fatal("physical probe kind guard", a)
			}
		}
		l := c.lanes[line]
		if l.delay == nil || *l.delay != 18 || l.probing || l.probeAt == nil || *l.probeAt != clock.Now().UnixMilli() {
			t.Fatal("completed probe round guard", line)
		}
	}

	// Compare external observations in trace order and associate each callback
	// with its checked native operation. No default handler can earn a receipt.
	checked := map[int]string{}
	logIndex := 0
	pendingLogs := []string{}
	completionID := 0
	for _, entry := range trace.Entries {
		var v map[string]any
		_ = json.Unmarshal(entry.Value, &v)
		guard := ""
		switch entry.Kind {
		case "initial-files":
			guard = "ordered saved settings loaded"
		case "completion":
			completionID++
			if v["id"] != float64(completionID) || entry.Seq == 0 || v["kind"] != trace.Entries[entry.Seq-1].Kind {
				t.Fatal("completion adjacency guard", entry.Seq)
			}
			if checked[entry.Seq-1] != "" {
				guard = checked[entry.Seq-1] + " completed"
			}
		case "file-completion":
			file, operation := js.Text(v["file"]), js.Text(v["operation"])
			baseName := filepath.Base(file)
			switch {
			case operation == "readFile" && (baseName == "settings.json" || baseName == "windows-undo.json" || baseName == "usage.json"):
				for _, r := range files.reads {
					if filepath.Base(r.Path) == baseName {
						if (r.Err == nil) != (v["ok"] == true) || r.Err != nil && (!errors.Is(r.Err, fs.ErrNotExist) || v["code"] != "ENOENT") {
							t.Fatal("actual store read result guard", entry.Seq)
						}
						guard = "actual Store/Core file result"
						break
					}
				}
			case operation == "readFile" && baseName == "package.json":
				if c.op.Version != "0.3.1" || v["ok"] != true {
					t.Fatal("compiled version guard")
				}
				guard = "host-supplied version replaces package read"
			case operation == "mkdir":
				if file != "/oracle/data" || v["ok"] != true || c.op.Settings == nil || c.op.Journal == nil {
					t.Fatal("store construction guard")
				}
				guard = "constructed native stores replace adapter directory setup"
			case operation == "readdir":
				if v["ok"] != false || v["code"] != "ERR_INVALID_ARG_TYPE" {
					t.Fatal("recorded cleanup failure guard")
				}
				guard = "complete revision replaces failed adapter directory cleanup"
			case strings.HasPrefix(baseName, "server.json.") || strings.HasPrefix(baseName, "usage.json."):
				if v["ok"] != true || (operation != "writeFile" && operation != "rename") {
					t.Fatal("atomic file completion guard")
				}
				name := "server.json"
				if strings.HasPrefix(baseName, "usage.json.") {
					name = "usage.json"
				}
				found := false
				for _, result := range files.fileResults {
					if result.Operation == operation && strings.HasPrefix(filepath.Base(result.Path), name+".") {
						if result.Err != nil {
							t.Fatal("native file completion failed", result)
						}
						if operation == "rename" && filepath.Base(result.Destination) != name {
							t.Fatal("native file rename destination", result)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("missing actual native file operation", operation, name)
				}
				guard = "actual atomic native publication"
			case strings.HasPrefix(baseName, "apps-") || strings.HasPrefix(baseName, "share-") || strings.HasPrefix(baseName, "cut-") || baseName == "engine-config.json":
				if v["ok"] != true || (operation != "writeFile" && operation != "rename") {
					t.Fatal("revision completion guard")
				}
				guard = "complete acknowledged revision replaces compiled file completion"
			}
		case "adapter-snapshot":
			var a []map[string]any
			check("adapter snapshot", json.Unmarshal(entry.Value, &a))
			equal("adapter inputs remain stable", a, adapters)
			guard = "production adapter observation"
		case "counter-sample":
			if v["value"] != nil || (v["alias"] != "Ethernet" && v["alias"] != "Wi-Fi") || len(c.meters) != 0 {
				t.Fatal("null physical counter guard")
			}
			guard = "physical counters remain unknown"
		case "write":
			file := filepath.Base(js.Text(v["file"]))
			switch file {
			case "server.json", "usage.json":
				got := files.data[filepath.Join("/test", file)]
				equal("persisted "+file, replayJSON(t, got), replayJSON(t, []byte(js.Text(v["text"]))))
				guard = "actual atomic native publication"
			default:
				if strings.HasPrefix(file, "apps-") || strings.HasPrefix(file, "share-") || strings.HasPrefix(file, "cut-") || file == "engine-config.json" {
					guard = "complete acknowledged revision and pin decisions"
				}
			}
		case "log":
			text := js.Text(v["text"])
			pendingLogs = append(pendingLogs, text)
			if strings.HasPrefix(text, "line readings come from PowerShell") {
				text = "line readings come from native workers"
			}
			if strings.HasPrefix(text, "network readings come from PowerShell") {
				text = "network readings come from isolated platform workers"
			}
			if logIndex >= len(files.logs) || files.logs[logIndex] != text {
				t.Fatal("ordered diagnostic condition guard", entry.Seq, text, files.logs)
			}
			logIndex++
			guard = "ordered native diagnostic returned"
		case "console":
			equal("session announcement", console, v["text"])
			guard = "native session announcement"
		case "async-result":
			operation := js.Text(v["operation"])
			if v["ok"] != true {
				t.Fatal("unexpected async failure", entry.Seq)
			}
			switch operation {
			case "log.append":
				if v["undefined"] != true || v["value"] != nil || len(pendingLogs) == 0 {
					t.Fatal("void log result guard")
				}
				equal("diagnostic completion args", v["args"], []any{pendingLogs[0]})
				pendingLogs = pendingLogs[1:]
				guard = "ordered native diagnostic returned"
			case "log.rotate":
				if v["undefined"] != true || v["value"] != nil || len(array(v["args"])) != 0 {
					t.Fatal("retired engine log rotation guard")
				}
				guard = "native diagnostic sink replaces private child log rotation"
			case "platform.isElevated":
				equal("elevation value", v["value"], c.elevated)
				guard = "production elevation result"
			case "platform.detectAdapters":
				equal("adapter result", v["value"], replayJSON(t, mustStartupJSON(t, adapters)))
				guard = "production adapter observation"
			case "platform.readMinimizeConnectionsPolicy":
				equal("policy result", v["value"], c.policy)
				guard = "production policy observation"
			case "platform.readDefaultRoutes":
				equal("route result", v["value"], replayJSON(t, mustStartupJSON(t, c.routes)))
				guard = "production physical route observation"
			default:
				if strings.HasPrefix(operation, "engine./proxies/line-") && strings.HasSuffix(operation, "/delay.json") {
					equal("probe JSON result", v["value"], map[string]any{"delay": float64(18)})
					guard = "completed physical probe round"
				}
			}
			if operation != "log.append" && operation != "log.rotate" && v["undefined"] != false {
				t.Fatal("value/undefined result guard", entry.Seq)
			}
		case "engine", "engine-reply":
			route := js.Text(v["route"])
			if strings.HasPrefix(route, "/proxies/lane-") {
				line := strings.TrimPrefix(route, "/proxies/lane-")
				if e.want.Lanes[line] == "" {
					t.Fatal("unknown native lane", line)
				}
				if entry.Kind == "engine" {
					equal("lane request method", v["method"], "PUT")
					equal("lane target", v["body"], map[string]any{"name": "line-" + e.want.Lanes[line]})
				} else {
					equal("lane reply status", v["status"], float64(200))
					equal("lane reply body", v["body"], map[string]any{})
				}
				guard = "complete acknowledged native lane revision"
			}
			if strings.HasSuffix(route, "/delay") {
				line := strings.TrimSuffix(strings.TrimPrefix(route, "/proxies/line-"), "/delay")
				if len(answers[line]) == 0 || v["method"] != "GET" {
					t.Fatal("physical probe request guard", v)
				}
				guard = "physical probe request"
			}
		case "probe-result":
			if v["status"] != float64(200) {
				t.Fatal("probe status guard")
			}
			equal("probe delay", v["body"], map[string]any{"delay": float64(18)})
			guard = "completed physical probe round"
		case "http":
			guard = replayStartupHTTP(t, c, entry, trace.Entries[entry.Seq+1], cmp)
		case "api":
			if entry.Seq > 0 && checked[entry.Seq-1] == "actual HTTP read and response" {
				guard = checked[entry.Seq-1]
			}
		}
		if guard != "" {
			checked[entry.Seq] = guard
		}
	}
	if logIndex != len(files.logs) || len(pendingLogs) != 0 || len(files.events) != 0 || len(files.outsideCloses) != 0 || clock.afterCalls.Load() != 0 || clock.Now().UnixMilli() != 1792411200000 {
		t.Fatal("startup leftover/timing guard")
	}
	check("native exhaustion", cmp.Finish())
	cursor := replayledger.NewCursor(rows)
	if len(rows) == 0 {
		t.Fatal("startup trace has no ledger binding")
	}
	for _, row := range rows {
		if checked[row.Seq] == "" {
			t.Fatalf("no behavioural guard for %s:%d %s", name, row.Seq, row.Kind)
		}
		check(checked[row.Seq], cursor.Consume(t, row.Hash, row.Seq, row.Disposition))
	}
	check("startup receipt", cursor.Receipt(t))
}

func mustStartupJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replayStartupHTTP(t *testing.T, c *Core, input, output replayledger.Entry, cmp *nativeTraceComparator) string {
	t.Helper()
	var in struct {
		Method, Route string
		Body          json.RawMessage
		Headers       map[string]string
	}
	if err := json.Unmarshal(input.Value, &in); err != nil {
		t.Fatal(err)
	}
	if in.Method != "GET" || in.Route != "/api/state" || output.Kind != "api" {
		t.Fatal("unsupported startup request/reply", in)
	}
	r := httptest.NewRequest(in.Method, "http://127.0.0.1:47821"+in.Route, bytes.NewReader(in.Body))
	for k, v := range in.Headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("X-Token", "native-replay")
	actualInput := mustStartupJSON(t, map[string]any{"method": r.Method, "route": r.URL.Path, "headers": in.Headers})
	if err := cmp.Observe(input.Seq, "http", actualInput); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&HTTP{Core: c, Port: 47821, Token: "native-replay"}).ServeHTTP(response, r)
	headers := map[string]string{}
	for k := range response.Header() {
		headers[k] = response.Header().Get(k)
	}
	actualOutput := mustStartupJSON(t, map[string]any{"status": response.Code, "headers": headers, "body": replayJSON(t, response.Body.Bytes())})
	if err := cmp.Observe(output.Seq, "api", actualOutput); err != nil {
		t.Fatal(err)
	}
	if err := cmp.Effects(); err != nil {
		t.Fatal("read-only API effects guard", err)
	}
	return "actual HTTP read and response"
}
