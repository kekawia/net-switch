package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// A pure boundary: compilation is production code, expectations are literals.
// fakeEngine supplies observation/ack plumbing, never the historical adapter.
// This does not claim to authenticate a service or acquire a native endpoint.
type nativeStartupEngine struct {
	*fakeEngine
	files      *memoryFiles
	check      func(engine.Revision) error
	want       policy.Config
	active     *policy.Policy
	applies    int
	guardError error
	probes     atomic.Uint64
	probeCheck func(engine.ProbeRequest, engine.ProbeResult)
	probeBegin func(engine.ProbeRequest)
	desired    *engine.Revision
}

func twoLineNativeConfig(pins map[string]string) policy.Config {
	return twoLineNativeConfigIDs("a1", "b2", pins)
}

func twoLineNativeConfigIDs(first, second string, pins map[string]string) policy.Config {
	return policy.Config{
		Lines:    []platform.Line{{ID: first, Interface: "Ethernet"}, {ID: second, Interface: "Wi-Fi"}},
		AppLines: pins, Shares: map[string]uint64{first: 500000, second: 500000},
		Lanes: map[string]string{first: first, second: second}, Blocked: []string{},
	}
}

func (e *nativeStartupEngine) compile(r engine.Revision) (*policy.Policy, error) {
	native, err := engine.NativeRevision(r, apppath.Windows)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(native.Config, e.want) || native.Hash != policy.Hash(e.want) {
		return nil, fmt.Errorf("native revision differs from literal: got %+v want %+v", native.Config, e.want)
	}
	return policy.Compile(native)
}

func (e *nativeStartupEngine) Start(ctx context.Context, p engine.Policy) (err error) {
	defer func() {
		if err != nil {
			e.guardError = err
		}
	}()
	if e.Snapshot().Status != "off" || e.active != nil || e.desired == nil {
		return fmt.Errorf("start precondition: expected off engine with staged desired revision and no active policy")
	}
	if !reflect.DeepEqual(p, e.desired.Policy) {
		return fmt.Errorf("start policy differs from staged desired revision")
	}
	if _, err = e.compile(*e.desired); err != nil {
		return err
	}
	e.files.recordOrder("native:start")
	if err = e.fakeEngine.Start(ctx, p); err != nil {
		return err
	}
	if _, err = e.Apply(ctx, *e.desired); err != nil {
		return err
	}
	if e.Snapshot().Status != "on" || e.Snapshot().Instance == "" || e.Snapshot().AppliedRevision != e.desired.Number {
		return fmt.Errorf("start result guard: missing instance or acknowledged revision")
	}
	e.files.recordOrder("native:started")
	return nil
}

func (e *nativeStartupEngine) ForgetLane(string) {} // complete revisions own lanes

func (e *nativeStartupEngine) CloseFlows(context.Context, engine.CloseRequest) (engine.CloseResult, error) {
	e.files.recordOrder("native:unexpected-close")
	return engine.CloseResult{}, fmt.Errorf("startup/pin changes must not close existing flows")
}

func (e *nativeStartupEngine) Probe(ctx context.Context, r engine.ProbeRequest) engine.ProbeResult {
	e.probes.Add(1)
	if e.probeBegin != nil {
		e.probeBegin(r)
	}
	result := e.fakeEngine.Probe(ctx, r)
	if e.probeCheck != nil {
		e.probeCheck(r, result)
	}
	return result
}

func TestNativeStartupReplay(t *testing.T) {
	t.Run("savedVersionOrder", func(t *testing.T) { replayNativeStartup(t, "savedVersionOrder") })
	t.Run("legacyCaseOrder", func(t *testing.T) { replayNativeStartup(t, "legacyCaseOrder") })
}

func (e *nativeStartupEngine) Apply(ctx context.Context, r engine.Revision) (ack engine.Acknowledgement, err error) {
	defer func() {
		if err != nil {
			e.guardError = err
		}
	}()
	before := e.Snapshot()
	if r.Number == 0 || r.Number <= before.AppliedRevision || before.Instance == "" {
		return ack, fmt.Errorf("apply precondition: revision must advance in a known instance")
	}
	if e.check != nil {
		if err = e.check(r); err != nil {
			return ack, err
		}
	}
	compiled, err := e.compile(r)
	if err != nil {
		return ack, err
	}
	if before.Status != "on" {
		// Match Remote.Apply: off-state acknowledgement stages desired policy,
		// but has no apply point and must not publish loaded state.
		e.desired = &r
		e.files.recordOrder("native:desired")
		return engine.Acknowledgement{Number: r.Number, Hash: r.Hash, Instance: before.Instance}, nil
	}
	e.files.recordOrder("native:apply")
	ack, err = e.fakeEngine.Apply(ctx, r)
	if err != nil {
		return ack, err
	}
	if ack.Number != r.Number || ack.Hash != r.Hash || ack.Instance != before.Instance || ack.Point <= before.AppliedPoint {
		return ack, fmt.Errorf("ack guard: revision/hash/instance/point mismatch: %+v", ack)
	}
	e.active = compiled
	e.applies++
	e.mu.Lock()
	e.s.StartedWith = &r.Policy
	e.mu.Unlock()
	e.files.recordOrder("native:ack")
	return ack, nil
}

// Compares one original-order selection. Translated values must be prepared by
// the caller's explicit mapping, never by silently filtering kinds or sorting.
// It intentionally cannot issue receipts: the owner must also check the native
// operation behind each observation before passing it to the ledger cursor.
type nativeTraceComparator struct {
	entries    []traceEntry
	next       int
	err        error
	effects    *[]string
	effectNext int
	replies    map[string]bool
	groups     map[string]bool
}

func (c *nativeTraceComparator) Effects(want ...string) error {
	if c.err != nil {
		return c.err
	}
	if c.effects == nil {
		return fmt.Errorf("native effect stream is not attached")
	}
	got := (*c.effects)[c.effectNext:]
	if !slices.Equal(got, want) {
		c.err = fmt.Errorf("native ordered effects: got %v want %v", got, want)
		return c.err
	}
	c.effectNext += len(got)
	return nil
}

func (c *nativeTraceComparator) Begin(name string) error {
	if c.groups == nil {
		c.groups = map[string]bool{}
	}
	if c.groups[name] {
		return fmt.Errorf("duplicate native group %s", name)
	}
	c.groups[name] = true
	return nil
}

func (c *nativeTraceComparator) End(name string) error {
	if !c.groups[name] {
		return fmt.Errorf("unknown native group %s", name)
	}
	delete(c.groups, name)
	return nil
}

func (c *nativeTraceComparator) Request(id string) error {
	if c.replies == nil {
		c.replies = map[string]bool{}
	}
	if id == "" || c.replies[id] {
		return fmt.Errorf("empty/duplicate native request %s", id)
	}
	c.replies[id] = true
	return nil
}

func (c *nativeTraceComparator) Reply(id string) error {
	if !c.replies[id] {
		return fmt.Errorf("unmatched native reply %s", id)
	}
	delete(c.replies, id)
	return nil
}

func (c *nativeTraceComparator) Observe(seq int, kind string, actual json.RawMessage) error {
	if c.err != nil {
		return c.err
	}
	fail := func(err error) error { c.err = err; return err }
	if c.next == len(c.entries) {
		return fail(fmt.Errorf("unexpected observation %d/%s after end", seq, kind))
	}
	want := c.entries[c.next]
	if seq != want.Seq || kind != want.Kind {
		return fail(fmt.Errorf("ordered observation guard: got %d/%s want %d/%s", seq, kind, want.Seq, want.Kind))
	}
	if !json.Valid(actual) || !json.Valid(want.Value) {
		return fail(fmt.Errorf("observation %d: invalid JSON", seq))
	}
	a, err := orderedTraceJSON(actual)
	if err != nil {
		return fail(err)
	}
	b, err := orderedTraceJSON(want.Value)
	if err != nil {
		return fail(err)
	}
	if !reflect.DeepEqual(a, b) {
		return fail(fmt.Errorf("observation %d/%s: %s", seq, kind, firstDifference(b, a, "$")))
	}
	c.next++
	return nil
}

func (c *nativeTraceComparator) Finish() error {
	if c.err != nil {
		return c.err
	}
	if c.next != len(c.entries) {
		return fmt.Errorf("missing behavioural observation at %d/%s", c.entries[c.next].Seq, c.entries[c.next].Kind)
	}
	if c.effects != nil && c.effectNext != len(*c.effects) {
		return fmt.Errorf("leftover native effects: %v", (*c.effects)[c.effectNext:])
	}
	if len(c.replies) != 0 {
		return fmt.Errorf("leftover native replies: %v", c.replies)
	}
	if len(c.groups) != 0 {
		return fmt.Errorf("leftover native groups: %v", c.groups)
	}
	return nil
}

func TestNativeTraceComparator(t *testing.T) {
	for _, kind := range []string{"effect", "reply", "group"} {
		t.Run("leftover-"+kind, func(t *testing.T) {
			effects := []string{}
			c := nativeTraceComparator{effects: &effects}
			switch kind {
			case "effect":
				effects = append(effects, "native:unexpected")
			case "reply":
				if err := c.Request("probe-1"); err != nil {
					t.Fatal(err)
				}
			case "group":
				if err := c.Begin("startup"); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Finish(); err == nil {
				t.Fatal("leftover native evidence accepted")
			}
		})
	}
	t.Run("settled-native-boundary", func(t *testing.T) {
		effects := []string{"native:apply", "native:ack"}
		c := nativeTraceComparator{effects: &effects}
		for _, err := range []error{c.Begin("revision"), c.Request("apply"), c.Reply("apply"), c.End("revision"), c.Effects("native:apply", "native:ack"), c.Finish()} {
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Reply("apply"); err == nil {
			t.Fatal("unmatched reply accepted")
		}
	})
	entries := []traceEntry{
		{Seq: 9, Kind: "write", Value: json.RawMessage(`{"appLines":{"first":"a1","second":"b2"},"optional":null}`)},
		{Seq: 10, Kind: "api", Value: json.RawMessage(`{"lines":["a1","b2"]}`)},
	}
	t.Run("complete", func(t *testing.T) {
		c := nativeTraceComparator{entries: entries}
		for _, e := range entries {
			if err := c.Observe(e.Seq, e.Kind, e.Value); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Finish(); err != nil {
			t.Fatal(err)
		}
		if err := c.Observe(10, "api", entries[1].Value); err == nil {
			t.Fatal("duplicate accepted")
		}
	})
	for _, tc := range []struct {
		name  string
		seq   int
		kind  string
		value string
	}{
		{"reordered-kind", 10, "api", `{"lines":["a1","b2"]}`},
		{"wrong-kind", 9, "api", string(entries[0].Value)},
		{"saved-order", 9, "write", `{"appLines":{"second":"b2","first":"a1"},"optional":null}`},
		{"absent-not-null", 9, "write", `{"appLines":{"first":"a1","second":"b2"}}`},
		{"wrong-value", 9, "write", `{"appLines":{"first":"b2","second":"b2"},"optional":null}`},
		{"invalid-json", 9, "write", `{} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := nativeTraceComparator{entries: entries}
			if err := c.Observe(tc.seq, tc.kind, json.RawMessage(tc.value)); err == nil {
				t.Fatal("bad observation accepted")
			}
			if c.next != 0 {
				t.Fatal("failed check advanced the cursor")
			}
			if err := c.Observe(9, "write", entries[0].Value); err == nil {
				t.Fatal("failure was erased by retry")
			}
			if err := c.Finish(); err == nil {
				t.Fatal("failed comparison finished")
			}
		})
	}
	t.Run("dropped-check", func(t *testing.T) {
		c := nativeTraceComparator{entries: entries}
		if err := c.Observe(9, "write", entries[0].Value); err != nil {
			t.Fatal(err)
		}
		if err := c.Finish(); err == nil {
			t.Fatal("missing API check accepted")
		}
	})
}

// Supporting evidence only. The startup completion/session/probe replay is not
// implemented here, so this test must not receive whole-trace ledger bindings.
func TestNativeStartupIdentityEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pins   map[string]string
		owners map[string]string
	}{
		{"appLine", map[string]string{}, map[string]string{`c:\apps\firefox.exe`: "a1"}},
		{"savedVersionOrder", map[string]string{`c:\discord\app-*\discord.exe`: "b2"}, map[string]string{
			`c:\discord\app-1.0.9\discord.exe`: "b2", `c:\discord\app-1.0.10\discord.exe`: "b2",
			`c:\discord\app-2.0.0\discord.exe`: "b2", `c:\discord\app-2.0.0\other.exe`: "a1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("../../tests/oracle/fixtures/" + tc.name + ".trace.json")
			if err != nil {
				t.Fatal(err)
			}
			var trace recordedTrace
			if err := json.Unmarshal(data, &trace); err != nil {
				t.Fatal(err)
			}
			// RawMessages retain the saved appLines insertion order through Store.
			var first struct{ Settings map[string]json.RawMessage }
			if err := json.Unmarshal(trace.Entries[0].Value, &first); err != nil {
				t.Fatal(err)
			}
			initial := map[string]any{}
			for k, v := range first.Settings {
				initial[k] = v
			}
			c, base, clock, files := testCore(t, initial)
			c.op.ServiceMode = true
			files.observeAllWrites = true
			base.ackPoint = 1
			e := &nativeStartupEngine{fakeEngine: base, files: files, want: twoLineNativeConfig(tc.pins)}
			c.op.Engine = e
			// These are explicit setup inputs, not consumed startup observations.
			if err := json.Unmarshal(trace.Entries[25].Value, &c.adapters); err != nil {
				t.Fatal(err)
			}
			c.policy = float64(1)
			if base.Snapshot().Status != "off" || e.applies != 0 || e.active != nil {
				t.Fatal("initial off guard")
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.ApplyPolicy(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.guardError != nil {
				t.Fatal(e.guardError)
			}
			if e.active == nil || e.applies == 0 {
				t.Fatal("missing compiled/acknowledged policy")
			}
			for owner, line := range tc.owners {
				d, err := e.active.Decide(platform.Owner{AppID: apppath.Normalize(owner, apppath.Windows)}, 40000, false, 1)
				if err != nil || d.Line != line || d.Revision != e.Snapshot().AppliedRevision {
					t.Fatalf("saved identity guard: %s got %+v (%v), want %s", owner, d, err, line)
				}
			}
			if tc.name == "appLine" {
				return
			} // pin/unpin suffix has its existing owner
			requestEntry, responseEntry := trace.Entries[129], trace.Entries[130]
			var request struct {
				Method, Route string
				Headers       map[string]string
			}
			if err := json.Unmarshal(requestEntry.Value, &request); err != nil {
				t.Fatal(err)
			}
			var expected struct {
				Status  int
				Headers map[string]string
				Body    map[string]any
			}
			if err := json.Unmarshal(responseEntry.Value, &expected); err != nil {
				t.Fatal(err)
			}
			operatorStateExpectation(expected.Body, false)
			// Use the trace's lowercase envelope field names.
			responseEntry.Value, err = json.Marshal(map[string]any{"status": expected.Status, "headers": expected.Headers, "body": expected.Body})
			if err != nil {
				t.Fatal(err)
			}
			comparator := nativeTraceComparator{entries: []traceEntry{requestEntry, responseEntry}}
			before, waits, at := len(files.order), clock.afterCalls.Load(), clock.Now()
			h := &HTTP{Core: c, Port: 47821, Token: "native-replay"}
			r := httptest.NewRequest(request.Method, "http://127.0.0.1:47821"+request.Route, bytes.NewReader(nil))
			r.Header.Set("X-Token", h.Token)
			actualRequest, _ := json.Marshal(map[string]any{"method": r.Method, "route": r.URL.Path, "headers": request.Headers})
			if err := comparator.Observe(129, "http", actualRequest); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, r)
			headers := map[string]string{}
			for k := range response.Header() {
				headers[k] = response.Header().Get(k)
			}
			actualResponse, err := json.Marshal(map[string]any{"status": response.Code, "headers": headers, "body": replayJSON(t, response.Body.Bytes())})
			if err != nil {
				t.Fatal(err)
			}
			if err := comparator.Observe(130, "api", actualResponse); err != nil {
				t.Fatal(err)
			}
			if err := comparator.Finish(); err != nil {
				t.Fatal(err)
			}
			if len(files.order) != before || clock.afterCalls.Load() != waits || !clock.Now().Equal(at) {
				t.Fatal("read-only snapshot guard: effects, wait or clock advance")
			}
		})
	}
}
