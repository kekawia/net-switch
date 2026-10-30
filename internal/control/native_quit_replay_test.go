package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// Reusable HTTP transport only: Control owns every action and its response.
type nativeSnapshotRecorder struct {
	*httptest.ResponseRecorder
	beforeWrite func()
}

func (w *nativeSnapshotRecorder) Write(b []byte) (int, error) {
	if fn := w.beforeWrite; fn != nil {
		w.beforeWrite = nil
		fn()
	}
	return w.ResponseRecorder.Write(b)
}

func replayNativeHTTP(t *testing.T, c *Core, trace replayledger.Trace, cmp *nativeTraceComparator, begin, end int, afterSnapshot ...func()) {
	t.Helper()
	var in struct {
		Method, Route string
		Body          json.RawMessage
		Headers       map[string]string
	}
	if err := json.Unmarshal(trace.Entries[begin].Value, &in); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(in.Method, "http://127.0.0.1:47821"+in.Route, bytes.NewReader(in.Body))
	r.Header.Set("X-Token", "native-replay")
	for k, v := range in.Headers {
		r.Header.Set(k, v)
	}
	input := map[string]any{"method": r.Method, "route": r.URL.RequestURI(), "headers": in.Headers}
	if len(in.Body) != 0 {
		input["body"] = replayJSON(t, in.Body)
	}
	if err := cmp.Observe(begin, "http", mustStartupJSON(t, input)); err != nil {
		t.Fatal(err)
	}
	w := &nativeSnapshotRecorder{ResponseRecorder: httptest.NewRecorder()}
	if len(afterSnapshot) > 0 {
		w.beforeWrite = afterSnapshot[0]
	}
	(&HTTP{Core: c, Port: 47821, Token: "native-replay"}).ServeHTTP(w, r)
	headers := map[string]string{}
	for k := range w.Header() {
		headers[k] = w.Header().Get(k)
	}
	if err := cmp.Observe(end, "api", mustStartupJSON(t, map[string]any{"status": w.Code, "headers": headers, "body": replayJSON(t, w.Body.Bytes())})); err != nil {
		t.Fatal(err)
	}
}

func replayNativeQuitFailure(t *testing.T, c *Core, e *nativeStartupEngine, clock *fakeClock, files *memoryFiles, trace replayledger.Trace, cmp *nativeTraceComparator, fc *startupFileCursor) map[int]string {
	t.Helper()
	before := e.Snapshot()
	if before.Status != "on" || before.Instance == "" || !c.WantsRouting() || c.quitting || c.ctx.Err() != nil || len(files.removes) != 0 {
		t.Fatal("quit starting lifecycle")
	}
	session, err := files.peekFile(filepath.Join("/test", "server.json"))
	if err != nil || len(session) == 0 {
		t.Fatal("quit starting session", err)
	}
	usage, err := files.peekFile(filepath.Join("/test", "usage.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Native status carries the service PID (Remote.nativeSnapshotLocked).
	// This is an identity observation, not a process started on this machine.
	e.mu.Lock()
	e.s.PID = 9001
	e.mu.Unlock()
	var mu sync.Mutex
	stopCount := 0
	var failure error
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
				return fmt.Errorf("stop before durable off intent")
			}
		}
		if c.WantsRouting() || c.ctx.Err() != nil {
			return fmt.Errorf("stop intent/cancellation order")
		}
		stopCount++
		files.recordOrder("native:stop")
		e.mu.Lock()
		defer e.mu.Unlock()
		e.calls = append(e.calls, "stop")
		if failure != nil {
			message := failure.Error()
			e.s.Status, e.s.Error = "error", &message
			return failure
		}
		e.s.Status, e.s.Error, e.s.PID = "off", nil, 0
		files.recordOrder("native:stopped")
		return nil
	}
	logs := len(files.logs)
	checked := map[int]string{}
	for i, step := range []struct{ input, begin, end int }{{135, 136, 146}, {147, 148, 174}} {
		mu.Lock()
		var message *string
		if err := json.Unmarshal(trace.Entries[step.input].Value, &message); err != nil {
			t.Fatal(err)
		}
		failure = nil
		if message != nil {
			failure = errors.New(*message)
		}
		mu.Unlock()
		if i == 0 && (message == nil || *message != "Access is denied") || i == 1 && message != nil {
			t.Fatal("quit fault order")
		}
		writes := len(files.writes)
		replayNativeHTTP(t, c, trace, cmp, step.begin, step.end)
		files.recordOrder("api")
		order := []string{"write:control-journal.json", "write:control-journal.json.bak", "log", "native:stop"}
		if i == 0 {
			order = append(order, "log", "log", "api")
			got, err := files.peekFile(filepath.Join("/test", "server.json"))
			if err != nil || !bytes.Equal(got, session) || len(files.removes) != 0 || len(files.writes) != writes+2 || c.quitting || c.ctx.Err() != nil || e.Snapshot().Status != "error" || e.Snapshot().PID != 9001 {
				t.Fatal("failed quit cleaned up or prevented retry", err)
			}
		} else {
			order = append(order, "native:stopped", "log", "write:usage.json", "remove:server.json", "log", "api")
			if _, err := files.peekFile(filepath.Join("/test", "server.json")); err == nil || !c.quitting || c.ctx.Err() != context.Canceled || e.Snapshot().Status != "off" || !reflect.DeepEqual(files.removes, []string{filepath.Join("/test", "server.json")}) {
				t.Fatal("successful quit cleanup/cancellation")
			}
			got, err := files.peekFile(filepath.Join("/test", "usage.json"))
			if err != nil || !bytes.Equal(got, usage) {
				t.Fatal("quit usage save", err)
			}
		}
		if err := cmp.Effects(order...); err != nil {
			t.Fatal(err)
		}
		checked[step.input], checked[step.begin], checked[step.end] = "staged stop outcome", "actual quit request", "complete quit response"
	}
	mu.Lock()
	stops := stopCount
	mu.Unlock()
	wantLogs := []string{"routing stopping", "routing error: Access is denied", "quit failed: Access is denied", "routing stopping", "routing off", "quit"}
	if stops != 2 || !reflect.DeepEqual(files.logs[logs:], wantLogs) || e.Snapshot().Instance != before.Instance || e.applies != 1 || e.probes.Load() != 2 || c.WantsRouting() {
		t.Fatal("quit outcomes and diagnostics", files.logs[logs:])
	}
	plan := []traceEntry{}
	add := func(kind string, v any) { plan = append(plan, traceEntry{Kind: kind, Value: mustStartupJSON(t, v)}) }
	appendLog := func(s string) {
		add("async-result", map[string]any{"operation": "log.append", "args": []any{s}, "ok": true, "value": nil, "undefined": true})
	}
	log := func(s string) { add("log", map[string]any{"text": s}); appendLog(s) }
	for _, s := range wantLogs[:3] {
		log(s)
	}
	add("log", map[string]any{"text": "routing stopping"})
	add("process-exit", map[string]any{"pid": 456, "code": 0})
	add("remove", map[string]any{"file": "/oracle/data/engine.pid"})
	appendLog("routing stopping")
	add("file-completion", map[string]any{"operation": "rm", "file": "/oracle/data/engine.pid", "ok": true})
	add("remove", map[string]any{"file": "/oracle/data/engine.pid"})
	add("file-completion", map[string]any{"operation": "rm", "file": "/oracle/data/engine.pid", "ok": true})
	log("routing off")
	add("remove", map[string]any{"file": "/oracle/data/server.json"})
	add("file-completion", map[string]any{"operation": "rm", "file": "/oracle/data/server.json", "ok": true})
	log("quit")
	next, completion := 0, 56
	for _, x := range trace.Entries[135:] {
		if x.Kind == "completion" {
			completion = checkHealthCompletion(t, trace, x.Seq, completion, checked)
			continue
		}
		if checked[x.Seq] != "" {
			continue
		}
		if x.Seq >= 163 && x.Seq <= 167 {
			if x.Kind == "write" {
				var v struct{ File, Text string }
				if err := json.Unmarshal(x.Value, &v); err != nil {
					t.Fatal(err)
				}
				if filepath.Base(v.File) != "usage.json" {
					t.Fatal("quit publication")
				}
				if err := fc.Publication("usage.json", []byte(v.Text)); err != nil {
					t.Fatal(err)
				}
			} else if ok, err := fc.Observe(x); !ok || err != nil {
				t.Fatal("quit file result", err)
			}
			checked[x.Seq] = "distinct final usage publication"
			continue
		}
		if next == len(plan) || x.Kind != plan[next].Kind || !reflect.DeepEqual(replayJSON(t, x.Value), replayJSON(t, plan[next].Value)) {
			t.Fatalf("quit ordered effect %d/%s, plan %d", x.Seq, x.Kind, next)
		}
		next++
		checked[x.Seq] = "ordered native stop outcome and verified cleanup"
	}
	if next != len(plan) {
		t.Fatal("unconsumed quit effects")
	}
	return checked
}
