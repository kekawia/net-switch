package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// Deliberately a partial mapping, not a disposition of the entire trace.
// Every selected entry has one assertion owner; all others remain uncovered.
const appLineMappingVersion = 1

type pinReplayStep struct {
	name                         string
	http, api, snapshot, barrier int
	settings, backup             int
	rules                        []int
	pins                         map[string]string
}

var pinReplaySteps = []pinReplayStep{
	{"pin", 135, 170, 168, 166, 158, 163, []int{138, 143, 148, 153}, map[string]string{`c:\apps\firefox.exe`: "b2"}},
	{"unpin", 171, 206, 204, 202, 194, 199, []int{174, 179, 184, 189}, map[string]string{}},
	{"read", 207, 210, 208, -1, -1, -1, nil, map[string]string{}},
}

// Uses no adapter, engine process, sockets, capture or OS routes. The embedded
// fake supplies only lifecycle/observation plumbing; Apply is wholly native.
type pinReplayEngine struct {
	*fakeEngine
	files   *memoryFiles
	check   func(engine.Revision) error
	want    policy.Config
	active  *policy.Policy
	applies int
}

func (e *pinReplayEngine) ForgetLane(string) {} // complete revisions own lanes

func (e *pinReplayEngine) CloseFlows(context.Context, engine.CloseRequest) (engine.CloseResult, error) {
	e.files.recordOrder("native:unexpected-close")
	return engine.CloseResult{}, fmt.Errorf("pin changes must not close existing flows")
}

func (e *pinReplayEngine) Apply(_ context.Context, r engine.Revision) (engine.Acknowledgement, error) {
	if e.check != nil {
		if err := e.check(r); err != nil {
			return engine.Acknowledgement{}, err
		}
	}
	native, err := engine.NativeRevision(r, apppath.Windows)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	if e.check != nil && (!reflect.DeepEqual(native.Config, e.want) || native.Hash != policy.Hash(e.want)) {
		return engine.Acknowledgement{}, fmt.Errorf("native revision differs from literal: got %+v want %+v", native.Config, e.want)
	}
	compiled, err := policy.Compile(native)
	if err != nil {
		return engine.Acknowledgement{}, err
	}
	e.files.recordOrder("native:apply")
	e.active = compiled
	e.applies++
	e.mu.Lock()
	e.s.Policy, e.s.StartedWith = r.Policy, &r.Policy
	e.s.AppliedRevision, e.s.AppliedHash = r.Number, r.Hash
	e.s.AppliedPoint++
	ack := engine.Acknowledgement{Number: r.Number, Hash: r.Hash, Instance: e.s.Instance, Point: e.s.AppliedPoint}
	e.mu.Unlock()
	e.files.recordOrder("native:ack")
	return ack, nil
}

func replayJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNativeAPIPinReplay(t *testing.T) {
	b, err := os.ReadFile("../../tests/oracle/fixtures/appLine.trace.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != "80a0365dc4be2eb7617807696f8ecd6948d01511288b1074b0311d31d9133c11" {
		t.Fatal("mapping needs review for changed trace", got)
	}
	var trace recordedTrace
	if err := json.Unmarshal(b, &trace); err != nil {
		t.Fatal(err)
	}
	if appLineMappingVersion != 1 || trace.Version != 1 || trace.Name != "appLine" || len(trace.Entries) != 211 {
		t.Fatal("unsupported mapping/trace")
	}
	consumed := map[int]string{}
	entry := func(seq int, kind, direction, owner string) json.RawMessage {
		t.Helper()
		if previous, ok := consumed[seq]; ok {
			t.Fatalf("entry %d consumed by both %s and %s", seq, previous, owner)
		}
		v := trace.Entries[seq]
		if v.Seq != seq || v.Kind != kind || v.Direction != direction {
			t.Fatalf("entry %d: expected %s/%s, got %+v", seq, direction, kind, v)
		}
		consumed[seq] = owner
		return v.Value
	}
	var initial struct{ Settings map[string]any }
	if err := json.Unmarshal(trace.Entries[0].Value, &initial); err != nil {
		t.Fatal(err)
	}
	c, base, clock, files := testCore(t, initial.Settings)
	c.op.ServiceMode = true
	e := &pinReplayEngine{fakeEngine: base, files: files}
	c.op.Engine = e
	// Recorded startup inputs establish the suffix precondition. Startup itself
	// is explicitly NOT consumed by this mapping.
	if err := json.Unmarshal(trace.Entries[25].Value, &c.adapters); err != nil {
		t.Fatal(err)
	}
	c.policy = float64(1)
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &HTTP{Core: c, Port: 47821, Token: "native-replay"}
	files.observeAllWrites = true
	startCalls := len(base.calls)
	for _, step := range pinReplaySteps {
		t.Run(step.name, func(t *testing.T) {
			orderStart, logsStart, eventsStart := len(files.order), len(files.logs), len(files.events)
			applies := e.applies
			previous := e.Snapshot()
			var input struct {
				Method, Route string
				Body          json.RawMessage
				Headers       map[string]string
			}
			if err := json.Unmarshal(entry(step.http, "http", "input", step.name), &input); err != nil {
				t.Fatal(err)
			}
			var expected struct {
				Status  int
				Headers map[string]string
				Body    json.RawMessage
			}
			if err := json.Unmarshal(entry(step.api, "api", "output", step.name), &expected); err != nil {
				t.Fatal(err)
			}
			wantBody := replayJSON(t, expected.Body).(map[string]any)
			settings := wantBody["settings"].(map[string]any)
			if !reflect.DeepEqual(settings["probeTargets"], []any{"1.1.1.1:443", "8.8.8.8:443"}) {
				t.Fatal("unrecognised legacy default probes")
			}
			// Locked design §4.5 adds Quad9 to defaults; saved bytes stay legacy.
			settings["probeTargets"] = []any{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
			var snapshot struct{ Now int64 }
			if err := json.Unmarshal(entry(step.snapshot, "state-snapshot", "input", step.name), &snapshot); err != nil || snapshot.Now != clock.Now().UnixMilli() {
				t.Fatal("snapshot clock differs", snapshot, err)
			}
			e.check = nil
			if step.settings >= 0 {
				var documentValues [2]any
				for i, seq := range []int{step.settings, step.backup} {
					var write struct{ File, Text string }
					if err := json.Unmarshal(entry(seq, "write", "output", step.name), &write); err != nil {
						t.Fatal(err)
					}
					documentValues[i] = replayJSON(t, []byte(write.Text))
				}
				for _, seq := range step.rules {
					entry(seq, "write", "output", step.name+" native revision")
				}
				var wait struct{ MS int }
				if err := json.Unmarshal(entry(step.barrier, "timer-completion", "input", step.name+" acknowledgement"), &wait); err != nil || wait.MS != 300 {
					t.Fatal("unknown reload barrier", wait, err)
				}
				e.want = policy.Config{
					Lines:    []platform.Line{{ID: "a1", Interface: "Ethernet"}, {ID: "b2", Interface: "Wi-Fi"}},
					AppLines: step.pins, Shares: map[string]uint64{"a1": 500000, "b2": 500000},
					Lanes: map[string]string{"a1": "a1", "b2": "b2"}, Blocked: []string{},
				}
				e.check = func(r engine.Revision) error {
					for i, name := range []string{"settings.json", "settings.json.bak"} {
						got, err := files.ReadFile(filepath.Join("/test", name))
						var value any
						if err != nil || json.Unmarshal(got, &value) != nil || !reflect.DeepEqual(value, documentValues[i]) {
							return fmt.Errorf("%s not committed before native apply: %s (%v)", name, got, err)
						}
					}
					for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
						got, err := files.ReadFile(filepath.Join("/test", name))
						if err != nil {
							return err
						}
						var journal struct {
							Desired  engine.Revision
							Settings map[string]any
						}
						if err := json.Unmarshal(got, &journal); err != nil || !reflect.DeepEqual(journal.Desired, r) {
							return fmt.Errorf("%s missing full desired revision: %s (%v)", name, got, err)
						}
						if !reflect.DeepEqual(journal.Settings, documentValues[0]) {
							return fmt.Errorf("journal/settings differ")
						}
					}
					if e.Snapshot().AppliedRevision != previous.AppliedRevision || r.Number <= previous.AppliedRevision {
						return fmt.Errorf("policy published before mutation or revision did not advance")
					}
					return nil
				}
			}
			req := httptest.NewRequest(input.Method, "http://127.0.0.1:47821"+input.Route, bytes.NewReader(input.Body))
			req.Header.Set("X-Token", h.Token)
			for k, v := range input.Headers {
				req.Header.Set(k, v)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			files.recordOrder("api")
			if response.Code != expected.Status || !reflect.DeepEqual(replayJSON(t, response.Body.Bytes()), wantBody) {
				t.Fatalf("response entry %d: status %d body %s; want %s", step.api, response.Code, response.Body, expected.Body)
			}
			if len(response.Header()) != len(expected.Headers) {
				t.Fatal("unexpected response headers", response.Header())
			}
			for k, v := range expected.Headers {
				if response.Header().Get(k) != v {
					t.Fatal("header differs", k)
				}
			}
			wantOrder := []string{"api"}
			wantApplies := applies
			if step.settings >= 0 {
				wantApplies++
				wantOrder = []string{"write:control-journal.json", "write:control-journal.json.bak", "write:settings.json", "write:settings.json.bak", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "api"}
			}
			if !reflect.DeepEqual(files.order[orderStart:], wantOrder) {
				t.Fatalf("semantic ledger: %v; want %v", files.order[orderStart:], wantOrder)
			}
			if e.applies != wantApplies || len(base.calls) != startCalls || len(files.logs) != logsStart || len(files.events) != eventsStart {
				t.Fatal("unexpected apply, lifecycle/closure, log or event", base.calls, files.logs[logsStart:])
			}
			if clock.Now().UnixMilli() != snapshot.Now {
				t.Fatal("native acknowledgement introduced a reload sleep")
			}
			for _, owner := range []string{`c:\apps\firefox.exe`, `c:\apps\other.exe`, ""} {
				want := "a1"
				if step.name == "pin" && owner == `c:\apps\firefox.exe` {
					want = "b2"
				}
				d, err := e.active.Decide(platform.Owner{AppID: owner}, 40000, false, 1)
				if err != nil || d.Line != want || d.Revision != e.Snapshot().AppliedRevision {
					t.Fatal("owner decision", owner, d, err)
				}
			}
		})
		if t.Failed() {
			break
		}
	}
	if len(consumed) != 23 {
		t.Fatalf("mapped %d entries, want exactly 23 (188 explicitly uncovered)", len(consumed))
	}
	t.Log("mapping v1: appLine 23 checked entries; 188 uncovered; other 24 traces uncovered")
}
