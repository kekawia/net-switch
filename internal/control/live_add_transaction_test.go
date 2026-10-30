package control

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func liveAddFixture(t *testing.T) (*Core, *fakeEngine, *fakeClock, *memoryFiles) {
	t.Helper()
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.op.Engine = liveUpdateEngine{e}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.op.LineID = func() string { return "c3" }
	c.adapters = append(c.adapters, map[string]any{"alias": "USB", "connected": true, "ipv4s": []any{"192.0.2.3"}})
	c.routes = append(c.routes, map[string]any{"interfaceAddress": "192.0.2.3"})
	return c, e, clock, files
}

func TestLiveAddFirstCommitIsComplete(t *testing.T) {
	for _, crash := range []bool{false, true} {
		name := "finish"
		if crash {
			name = "crash-at-desired-commit"
		}
		t.Run(name, func(t *testing.T) {
			c, e, clock, files := liveAddFixture(t)
			before := c.revision
			if c.lanes["c3"] != nil || e.Snapshot().AppliedRevision != before {
				t.Fatal("starting revision/lane")
			}
			commits := 0
			var captured *memoryFiles
			var visible map[string]any
			prepared := false
			marker := new(int)
			c.op.Checkpoint = func(point string) {
				if point != "control-after-desired-commit" {
					return
				}
				commits++
				files.mu.Lock()
				captured = &memoryFiles{data: map[string][]byte{}}
				for k, v := range files.data {
					captured.data[k] = append([]byte(nil), v...)
				}
				files.mu.Unlock()
				c.mu.Lock()
				added := c.lanes["c3"]
				prepared = added != nil && added.sampled && added.health.Up != nil && *added.health.Up
				c.mu.Unlock()
				visible = c.State()
				if crash {
					panic(marker)
				}
			}
			var panicked any
			var err error
			func() {
				defer func() { panicked = recover() }()
				err = c.changeLines(context.Background(), "/api/lines/add", map[string]any{"alias": "USB"})
			}()
			if err != nil || crash && panicked != marker || !crash && panicked != nil || commits != 1 || captured == nil {
				t.Fatal("desired checkpoint", err, panicked, commits)
			}
			var mirror struct{ Lines []any }
			if err := json.Unmarshal(captured.data[c.op.Settings.File], &mirror); err != nil || len(mirror.Lines) != 2 {
				t.Fatal("checkpoint must precede settings mirror", err)
			}
			rows := visible["lines"].([]any)
			if len(rows) != 3 || rows[2].(map[string]any)["connected"] != true {
				t.Error("published unsampled added line")
			}
			recovered, _, _, _ := testCoreWithFilesMode(t, captured, clock, true)
			if recovered.pendingRevision == nil || recovered.pendingRevision.Policy.Lanes["c3"] != "c3" || recovered.pendingRevision.Number != before+1 || recovered.revision != before+1 {
				t.Fatal("recovered incomplete/extra desired revision", recovered.pendingRevision, recovered.revision, before)
			}
			if !prepared {
				t.Fatal("desired commit preceded lane preparation")
			}
			if c.revision != before+1 {
				t.Fatal("add minted a second revision", c.revision, before)
			}
			if crash {
				if e.Snapshot().AppliedRevision != before {
					t.Fatal("engine mutated before crash checkpoint")
				}
			} else if e.Snapshot().AppliedRevision != before+1 || e.Snapshot().Policy.Lanes["c3"] != "c3" {
				t.Fatal("applied wrong desired revision")
			}
		})
	}
}

func TestLiveAddDoesNotSampleExistingLines(t *testing.T) {
	for _, change := range []string{"address", "route"} {
		t.Run(change, func(t *testing.T) {
			c, _, clock, _ := liveAddFixture(t)
			clock.advance(5000)
			if c.lanes["a1"].health.AddressMisses != 0 || c.lanes["a1"].health.RouteMisses != 0 {
				t.Fatal("starting misses")
			}
			before, _ := json.Marshal(c.lanes["a1"].health)
			if change == "address" {
				c.adapters[0]["ipv4s"] = []any{}
			} else {
				c.routes = []map[string]any{{"interfaceAddress": "192.0.2.2"}, {"interfaceAddress": "192.0.2.3"}}
				c.routesAt = c.now()
				c.routesSequence++
			}
			if err := c.changeLines(context.Background(), "/api/lines/add", map[string]any{"alias": "USB"}); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(c.lanes["a1"].health)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("live add resampled existing line early", string(before), string(after))
			}
			if !c.lanes["c3"].sampled {
				t.Fatal("new line was not sampled")
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if change == "address" && c.lanes["a1"].health.AddressMisses != 1 || change == "route" && c.lanes["a1"].health.RouteMisses != 1 {
				t.Fatal("next poll did not observe staged change", c.lanes["a1"].health)
			}
		})
	}
}

func TestLiveAddBeforeFirstReattachedPoll(t *testing.T) {
	c, e, clock, files := liveAddFixture(t)
	recovered, _, _, _ := testCoreWithFilesMode(t, files, clock, true)
	recovered.op.Engine = liveUpdateEngine{e}
	recovered.op.LineID = c.op.LineID
	recovered.adapters = c.adapters
	recovered.routes = c.routes
	if err := recovered.SignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recovered.initialSampled || recovered.lanes["a1"].sampled || recovered.lanes["b2"].sampled || e.Snapshot().Status != "on" {
		t.Fatal("reattach preconditions")
	}
	if err := recovered.changeLines(context.Background(), "/api/lines/add", map[string]any{"alias": "USB"}); err != nil {
		t.Fatal(err)
	}
	if recovered.initialSampled || recovered.lanes["a1"].sampled || recovered.lanes["b2"].sampled || !recovered.lanes["c3"].sampled {
		t.Error("selective sample claimed a complete initial sample")
	}
	if err := recovered.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !recovered.initialSampled || !recovered.lanes["a1"].sampled || !recovered.lanes["b2"].sampled {
		t.Fatal("supervisor skipped initial sampling")
	}
}

func TestLiveAddJournalFailureDiscardsPreparedLane(t *testing.T) {
	c, e, _, files := liveAddFixture(t)
	before := e.Snapshot()
	files.failPrefix = c.op.Journal.File + "."
	if err := c.changeLines(context.Background(), "/api/lines/add", map[string]any{"alias": "USB"}); err == nil {
		t.Fatal("journal failure accepted")
	}
	if len(c.itemsLocked()) != 2 || c.lanes["c3"] != nil || c.revision != before.AppliedRevision || !reflect.DeepEqual(e.Snapshot(), before) {
		t.Fatal("uncommitted added lane survived")
	}
}

