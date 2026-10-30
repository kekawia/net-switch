package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	controlplatform "github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// The HTTP request selects the flows through real Control. The pure flow table
// proves the selected IDs existed and that on-target and newer flows survive.
func replayNativeReconnect(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator) map[int]string {
	t.Helper()
	shared := trace.Name == "reconnectShared"
	before := e.Snapshot()
	if before.Status != "on" || before.AppliedRevision == 0 || len(c.tracker.Snapshot(nil)) != 0 || c.outside.Get(`c:\apps\firefox.exe`) != nil {
		t.Fatal("reconnect requires running instance and initially empty observations")
	}
	for _, id := range []string{"a1", "b2"} {
		l := c.lanes[id]
		if l.health.Up == nil || !*l.health.Up || l.probing || l.delay == nil || *l.delay != 18 {
			t.Fatal("reconnect requires completed healthy lines", id)
		}
	}
	var supplied []engine.Connection
	if err := json.Unmarshal(trace.Entries[129].Value, &supplied); err != nil || len(supplied) != 2 {
		t.Fatal("reconnect input", err)
	}
	wire := replayJSON(t, trace.Entries[129].Value)
	wantIDs := []string{"off-line", "right-line"}
	if shared {
		wantIDs = []string{"shared-main", "shared-second"}
	}
	for i := range supplied {
		x := &supplied[i]
		if x.ID != wantIDs[i] || x.Metadata.ProcessPath != `C:\Apps\Firefox.exe` || !reflect.DeepEqual(x.Chains, []string{"line-" + []string{"a1", "b2"}[i]}) || x.Download != 10 || x.Upload != 2 || x.Start != "2026-10-19T12:00:00Z" {
			t.Fatal("flow input identity and physical line", x)
		}
		x.ID = fmt.Sprintf("%s:%d", before.Instance, i+1)
	}
	var mu sync.Mutex
	reads, closes, outsideCalls := 0, 0, 0
	e.readConnections = func(context.Context) ([]engine.Connection, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		files.recordOrder("native:connections")
		return append([]engine.Connection{}, supplied...), nil
	}
	checkJournal := func(request *engine.CloseRequest) error {
		for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
			b, err := files.peekFile(filepath.Join("/test", name))
			if err != nil {
				return err
			}
			var j struct {
				Closures []closureIntent
				Desired  engine.Revision
				Wanted   bool
			}
			if err := json.Unmarshal(b, &j); err != nil {
				return err
			}
			if !j.Wanted || j.Desired.Number != before.AppliedRevision {
				return fmt.Errorf("reconnect changed desired intent")
			}
			if request == nil {
				if len(j.Closures) != 0 {
					return fmt.Errorf("unexpected pending closure: %+v", j.Closures)
				}
			} else if len(j.Closures) != 1 || j.Closures[0].ID != request.OperationID || j.Closures[0].Purpose != "reconnect" || j.Closures[0].Label != `c:\apps\firefox.exe` || j.Closures[0].Revision != before.AppliedRevision || !reflect.DeepEqual(j.Closures[0].Request, *request) {
				return fmt.Errorf("closure not durable in %s: %+v", name, j.Closures)
			}
		}
		return nil
	}
	if err := checkJournal(nil); err != nil {
		t.Fatal("starting journal", err)
	}
	e.closeCheck = func(r engine.CloseRequest) (engine.CloseResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if shared || closes != 0 || r.Instance != before.Instance || r.OperationID == "" || !r.StartedBefore.Equal(clock.Now()) || r.StartedBeforePoint != 0 || r.BeforeRevision != 0 || r.Line != "" || !reflect.DeepEqual(r.ConnectionIDs, []string{before.Instance + ":1"}) {
			return engine.CloseResult{}, fmt.Errorf("wrong reconnect selection: %+v", r)
		}
		if err := checkJournal(&r); err != nil {
			return engine.CloseResult{}, err
		}
		result, err := checkReconnectFlowIDs(supplied, r, e.want)
		if err != nil {
			return engine.CloseResult{}, err
		}
		closes++
		files.recordOrder("native:close")
		return result, nil
	}
	clock.at = clock.Now().Add(time.Second)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cmp.Effects("native:connections", "platform:app-info"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.tracker.ConnectionIDsOffLine(`c:\apps\firefox.exe`, "b2"), []string{before.Instance + ":1"}) || len(c.tracker.Snapshot(nil)) != 1 {
		t.Fatal("poll did not establish the exact off-target held flow")
	}
	var helper struct{ Line string }
	if err := json.Unmarshal(trace.Entries[142].Value, &helper); err != nil || !c.HelperLine([]byte(helper.Line)) {
		t.Fatal("outside input", err)
	}
	outsideID := "192.0.2.1:1234>203.0.113.1:443|42|2026-10-19T11:00:00Z"
	if !reflect.DeepEqual(c.outside.IDsOf(`c:\apps\firefox.exe`), []string{outsideID}) || !reflect.DeepEqual(c.outside.IDsOffLine(`c:\apps\firefox.exe`, "b2"), []string{outsideID}) {
		t.Fatal("outside socket must exist on a1 before reconnect")
	}
	if err := cmp.Effects(); err != nil {
		t.Fatal(err)
	}
	p := c.op.Platform.(*fakePlatform)
	p.mu.Lock()
	p.recordClose = func(v any) {
		mu.Lock()
		defer mu.Unlock()
		want := []controlplatform.TCPSelector{{Tuple: apps.Tuple{Local: "192.0.2.1", LPort: 1234, Remote: "203.0.113.1", RPort: 443, PID: 42, Created: "2026-10-19T11:00:00Z"}}}
		if !reflect.DeepEqual(v, want) {
			t.Errorf("outside selector: got %+v want %+v", v, want)
		}
		if err := checkJournal(nil); err != nil {
			t.Error("outside close before durable completion", err)
		}
		outsideCalls++
	}
	p.mu.Unlock()
	var in struct {
		Method, Route string
		Body          json.RawMessage
		Headers       map[string]string
	}
	if err := json.Unmarshal(trace.Entries[143].Value, &in); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(in.Method, "http://127.0.0.1:47821"+in.Route, bytes.NewReader(in.Body))
	r.Header.Set("X-Token", "native-replay")
	if err := cmp.Observe(143, "http", mustStartupJSON(t, map[string]any{"method": r.Method, "route": r.URL.Path, "body": replayJSON(t, in.Body), "headers": in.Headers})); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&HTTP{Core: c, Port: 47821, Token: "native-replay"}).ServeHTTP(response, r)
	files.recordOrder("api")
	headers := map[string]string{}
	for k := range response.Header() {
		headers[k] = response.Header().Get(k)
	}
	if err := cmp.Observe(len(trace.Entries)-1, "api", mustStartupJSON(t, map[string]any{"status": response.Code, "headers": headers, "body": replayJSON(t, response.Body.Bytes())})); err != nil {
		t.Fatal(err)
	}
	order := []string{"platform:close-tcp", "log", "api"}
	if !shared {
		order = append([]string{"write:control-journal.json", "write:control-journal.json.bak", "native:close", "write:control-journal.json", "write:control-journal.json.bak"}, order...)
	}
	if err := cmp.Effects(order...); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	wantCloses, total := 1, 2
	if shared {
		wantCloses, total = 0, 1
	}
	if reads != 1 || closes != wantCloses || outsideCalls != 1 || !reflect.DeepEqual(e.Snapshot(), before) || e.applies != 1 || e.probes.Load() != 2 || len(files.events) != 0 || len(c.meters) != 0 {
		t.Fatal("reconnect changed session/policy or repeated effects", reads, closes, outsideCalls)
	}
	note := fmt.Sprintf("reconnect c:\\apps\\firefox.exe: closed %d, failed 0 (codes ), already gone 0", total)
	if files.logs[len(files.logs)-1] != note {
		t.Fatal("reconnect diagnostic")
	}
	// Independent ordered projection: every old result is tied to the just
	// checked native read, closure, platform operation or diagnostic.
	plan := []traceEntry{}
	add := func(kind string, v any) { plan = append(plan, traceEntry{Kind: kind, Value: mustStartupJSON(t, v)}) }
	add("connections", wire)
	add("clock-tick", map[string]any{"now": clock.Now().UnixMilli()})
	for _, alias := range []string{"Ethernet", "Wi-Fi"} {
		add("counter-sample", map[string]any{"alias": alias, "value": nil})
	}
	add("engine", map[string]any{"route": "/connections", "method": "GET"})
	add("engine-reply", map[string]any{"route": "/connections", "status": 200, "body": map[string]any{"connections": wire}})
	add("async-result", map[string]any{"operation": "engine./connections.json", "args": []any{}, "ok": true, "value": map[string]any{"connections": wire}, "undefined": false})
	for i := 0; i < 2; i++ {
		add("clock-tick", map[string]any{"now": clock.Now().UnixMilli()})
	}
	add("helper-line", map[string]any{"line": helper.Line})
	if !shared {
		add("engine", map[string]any{"route": "/connections/off-line", "method": "DELETE"})
		add("engine-reply", map[string]any{"route": "/connections/off-line", "status": 200, "body": map[string]any{}})
	}
	items := []any{map[string]any{"local": "192.0.2.1", "lport": 1234, "remote": "203.0.113.1", "rport": 443, "pid": 42, "created": "2026-10-19T11:00:00Z"}}
	add("outside-close", map[string]any{"items": items})
	add("async-result", map[string]any{"operation": "platform.closeTcpConnections", "args": []any{items}, "ok": true, "value": map[string]any{"closed": 1, "failed": 0, "gone": 0, "codes": []any{}}, "undefined": false})
	add("log", map[string]any{"text": note})
	add("async-result", map[string]any{"operation": "log.append", "args": []any{note}, "ok": true, "value": nil, "undefined": true})
	checked := map[int]string{143: "actual reconnect HTTP request", len(trace.Entries) - 1: "complete reconnect response"}
	next, completion := 0, 53
	for _, x := range trace.Entries[129:] {
		if x.Kind == "completion" {
			completion = checkHealthCompletion(t, trace, x.Seq, completion, checked)
			continue
		}
		if checked[x.Seq] != "" {
			continue
		}
		if next == len(plan) || x.Kind != plan[next].Kind || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, plan[next].Value)) {
			t.Fatalf("ordered reconnect evidence at %d/%s, plan %d", x.Seq, x.Kind, next)
		}
		next++
		checked[x.Seq] = "exact reconnect native operation and result"
	}
	if next != len(plan) {
		t.Fatal("unconsumed reconnect observations")
	}
	return checked
}

func checkReconnectFlowIDs(input []engine.Connection, request engine.CloseRequest, current policy.Config) (engine.CloseResult, error) {
	table := flows.New(flows.Defaults(), nil)
	defer table.CloseAll()
	admit := func(i int, config policy.Config) error {
		if _, err := table.Apply(policy.Revision{N: uint64(i + 1), Hash: policy.Hash(config), Config: config}); err != nil {
			return err
		}
		ticket, err := table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort(fmt.Sprintf("198.18.0.2:%d", 40000+i)), Destination: netip.MustParseAddrPort("203.0.113.9:443")})
		if err != nil {
			return err
		}
		if _, err := ticket.Resolve(platform.Owner{AppID: `c:\apps\firefox.exe`}); err != nil {
			ticket.Close()
			return err
		}
		ticket.SetCancel(ticket.Close)
		return nil
	}
	for i, line := range []string{"a1", "b2"} {
		if err := admit(i, twoLineNativeConfig(map[string]string{`c:\apps\firefox.exe`: line})); err != nil {
			return engine.CloseResult{}, err
		}
	}
	before, err := table.Page("")
	if err != nil || len(before.Flows) != 2 {
		return engine.CloseResult{}, fmt.Errorf("held flows absent: %v", err)
	}
	for i, f := range before.Flows {
		if input[i].ID != fmt.Sprintf("%s:%d", request.Instance, f.ID) || f.Line != []string{"a1", "b2"}[i] {
			return engine.CloseResult{}, fmt.Errorf("held flow bijection")
		}
	}
	if _, err := table.Apply(policy.Revision{N: 3, Hash: policy.Hash(current), Config: current}); err != nil {
		return engine.CloseResult{}, err
	}
	// A new off-target flow arriving after selection must not be swept in.
	if err := admit(3, twoLineNativeConfig(map[string]string{`c:\apps\firefox.exe`: "a1"})); err != nil {
		return engine.CloseResult{}, err
	}
	ids := []uint64{}
	for _, id := range request.ConnectionIDs {
		var n uint64
		if _, err := fmt.Sscanf(id, request.Instance+":%d", &n); err != nil {
			return engine.CloseResult{}, err
		}
		ids = append(ids, n)
	}
	result, err := table.CloseFlows(flows.Selector{IDs: ids}, 0)
	if err != nil || result.Closed != 1 || result.Gone != 0 || result.Failed != 0 {
		return engine.CloseResult{}, fmt.Errorf("exact ID closure: %+v %v", result, err)
	}
	after, err := table.Page("")
	if err != nil || len(after.Flows) != 2 || !reflect.DeepEqual(after.Flows[0], before.Flows[1]) || after.Flows[1].ID != 3 || after.Flows[1].Line != "a1" {
		return engine.CloseResult{}, fmt.Errorf("on-target/newer flow survival: %+v %v", after, err)
	}
	return engine.CloseResult{Closed: result.Closed, Failed: result.Failed, Gone: result.Gone}, nil
}
