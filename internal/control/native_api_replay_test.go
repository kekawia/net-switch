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
	"slices"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// Deliberately a partial mapping, not a disposition of the entire trace.
// Every selected entry has one assertion owner; startup owns the remainder.
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
	traceHash := fmt.Sprintf("%x", sha256.Sum256(b))
	if traceHash != "80a0365dc4be2eb7617807696f8ecd6948d01511288b1074b0311d31d9133c11" {
		t.Fatal("mapping needs review for changed trace", traceHash)
	}
	var trace recordedTrace
	if err := json.Unmarshal(b, &trace); err != nil {
		t.Fatal(err)
	}
	if appLineMappingVersion != 1 || trace.Version != 1 || trace.Name != "appLine" || len(trace.Entries) != 211 {
		t.Fatal("unsupported mapping/trace")
	}
	var initial struct{ Settings map[string]any }
	if err := json.Unmarshal(trace.Entries[0].Value, &initial); err != nil {
		t.Fatal(err)
	}
	c, base, clock, files := testCore(t, initial.Settings)
	c.op.ServiceMode = true
	base.ackPoint = 1
	e := &nativeStartupEngine{fakeEngine: base, files: files, want: twoLineNativeConfig(map[string]string{})}
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
	replayNativePinSuffix(t, c, e, clock, files, trace, traceHash, true, nil)
}

// Shared with startup replay; only the original API subtests emit its 23 receipts.
func replayNativePinSuffix(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace recordedTrace, traceHash string, register bool, observer *nativeTraceComparator) map[int]string {
	t.Helper()
	base := e.fakeEngine
	consumed := map[int]string{}
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
	h := &HTTP{Core: c, Port: 47821, Token: "native-replay"}
	clock.afterImmediate = true
	platformCalls := func() int {
		p := c.op.Platform.(*fakePlatform)
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.calls)
	}
	files.observeAllWrites = true
	for _, step := range pinReplaySteps {
		t.Run(step.name, func(t *testing.T) {
			checkedBefore := len(consumed)
			orderStart, logsStart, eventsStart := len(files.order), len(files.logs), len(files.events)
			applies := e.applies
			callsBefore := len(base.calls)
			previous := e.Snapshot()
			waitsBefore, probesBefore, platformBefore := clock.afterCalls.Load(), e.probes.Load(), platformCalls()
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
				before, err := files.peekFile(filepath.Join("/test", "settings.json"))
				if err != nil {
					t.Fatal(err)
				}
				if reflect.DeepEqual(replayJSON(t, before), documentValues[0]) {
					t.Fatal("precondition: settings.json already matches the requested change")
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
						got, err := files.peekFile(filepath.Join("/test", name))
						var value any
						if err != nil || json.Unmarshal(got, &value) != nil || !reflect.DeepEqual(value, documentValues[i]) {
							return fmt.Errorf("%s not committed before native apply: %s (%v)", name, got, err)
						}
					}
					for _, name := range []string{"control-journal.json", "control-journal.json.bak"} {
						got, err := files.peekFile(filepath.Join("/test", name))
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
			if observer != nil {
				value := map[string]any{"method": req.Method, "route": req.URL.Path, "headers": input.Headers}
				if len(input.Body) != 0 {
					value["body"] = replayJSON(t, input.Body)
				}
				if err := observer.Observe(step.http, "http", mustStartupJSON(t, value)); err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			files.recordOrder("api")
			if observer != nil {
				headers := map[string]string{}
				for k := range response.Header() {
					headers[k] = response.Header().Get(k)
				}
				value := map[string]any{"status": response.Code, "headers": headers, "body": replayJSON(t, response.Body.Bytes())}
				if err := observer.Observe(step.api, "api", mustStartupJSON(t, value)); err != nil {
					t.Fatal(err)
				}
			}
			if e.guardError != nil {
				t.Fatalf("native apply guard: %v", e.guardError)
			}
			if calls := clock.afterCalls.Load() - waitsBefore; calls != 0 {
				t.Fatalf("request called Clock.After %d times; native acknowledgement must not add a reload wait", calls)
			}
			if e.probes.Load() != probesBefore || platformCalls() != platformBefore {
				t.Fatalf("request performed unexpected I/O: probes %d -> %d, platform calls %d -> %d", probesBefore, e.probes.Load(), platformBefore, platformCalls())
			}
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
			var wantCalls []string
			wantApplies := applies
			if step.settings >= 0 {
				wantApplies++
				wantCalls = []string{"apply"}
				wantOrder = []string{"write:control-journal.json", "write:control-journal.json.bak", "write:settings.json", "write:settings.json.bak", "write:control-journal.json", "write:control-journal.json.bak", "native:apply", "native:ack", "api"}
			}
			if !reflect.DeepEqual(files.order[orderStart:], wantOrder) {
				t.Fatalf("semantic ledger: %v; want %v", files.order[orderStart:], wantOrder)
			}
			if e.applies != wantApplies || !slices.Equal(base.calls[callsBefore:], wantCalls) || len(files.logs) != logsStart || len(files.events) != eventsStart {
				t.Fatal("unexpected apply, lifecycle/closure, log or event", base.calls, files.logs[logsStart:])
			}
			if clock.Now().UnixMilli() != snapshot.Now {
				t.Fatal("response returned at a different snapshot time")
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
			if observer != nil {
				if err := observer.Effects(wantOrder...); err != nil {
					t.Fatal(err)
				}
			}
			if !register {
				return
			}
			// Select only this executing test's registered rows, in original
			// sequence order. No receipt is earned until every check above passes.
			var rows []replayledger.Row
			for _, row := range report.Rows {
				if row.Hash == traceHash && row.Assertion == "internal/control/native_api_replay_test.go#"+t.Name() {
					if consumed[row.Seq] != step.name && consumed[row.Seq] != step.name+" native revision" && consumed[row.Seq] != step.name+" acknowledgement" {
						t.Fatalf("registered entry %d has no behavioral check in %s", row.Seq, t.Name())
					}
					rows = append(rows, row)
				}
			}
			if len(rows) != len(consumed)-checkedBefore {
				t.Fatalf("registered %d entries but checked %d", len(rows), len(consumed)-checkedBefore)
			}
			cursor := replayledger.NewCursor(rows)
			for _, row := range rows {
				if err := cursor.Consume(t, row.Hash, row.Seq, row.Disposition); err != nil {
					t.Fatal(err)
				}
			}
			if err := cursor.Receipt(t); err != nil {
				t.Fatal(err)
			}
		})
		if t.Failed() {
			break
		}
	}
	if len(consumed) != 23 {
		t.Fatalf("mapped %d entries, want exactly 23 (188 outside this owner)", len(consumed))
	}
	t.Log("mapping v1: appLine 23 checked entries; all other entries belong to separate replay owners")
	return consumed
}
