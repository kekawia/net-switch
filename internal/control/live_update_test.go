package control

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

// These are pure Control boundary tests, not installed traffic evidence. The
// native remote publishes the acknowledged policy as StartedWith; the legacy
// fake deliberately retains the initial policy for the frozen replay.
type liveUpdateEngine struct{ *fakeEngine }

func (e liveUpdateEngine) Apply(ctx context.Context, r engine.Revision) (engine.Acknowledgement, error) {
	a, err := e.fakeEngine.Apply(ctx, r)
	if err == nil {
		e.mu.Lock()
		p := r.Policy
		e.s.StartedWith = &p
		e.mu.Unlock()
	}
	return a, err
}

func TestServiceLiveNetworkUpdate(t *testing.T) {
	for _, change := range []string{"binding", "ipv6-on", "ipv6-off"} {
		t.Run(change, func(t *testing.T) {
			c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			c.op.Engine = liveUpdateEngine{e}
			for _, a := range c.adapters {
				a["ipv6"] = change == "ipv6-off"
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := e.Snapshot()
			e.calls = nil
			if change == "binding" {
				items := c.itemsLocked()
				items[1].Alias = "Renamed Wi-Fi"
				if err := c.save(map[string]any{"lines": items}); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, a := range c.adapters {
					a["ipv6"] = change == "ipv6-on"
				}
				if err := c.Supervise(context.Background()); err != nil {
					t.Fatal(err)
				}
				if len(e.calls) != 0 {
					t.Fatalf("IPv6 changed before settling: %v", e.calls)
				}
				clock.at = clock.at.Add(30 * time.Second)
			}
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(e.calls, []string{"apply"}) {
				t.Fatalf("live change must only apply, got %v", e.calls)
			}
			after := e.Snapshot()
			if after.Instance != before.Instance || !after.StartedAt.Equal(before.StartedAt) || after.AppliedRevision <= before.AppliedRevision {
				t.Fatal("live update replaced lifetime or did not publish a revision")
			}
			e.calls = nil
			if err := c.Supervise(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(e.calls) != 0 {
				t.Fatalf("acknowledged change repeated: %v", e.calls)
			}
		})
	}
}

func TestServiceLiveLineActions(t *testing.T) {
	for _, action := range []string{"add", "remove", "order", "update"} {
		t.Run(action, func(t *testing.T) {
			c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			c.op.Engine = liveUpdateEngine{e}
			c.adapters = append(c.adapters, map[string]any{"alias": "USB", "connected": true})
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			e.calls = nil
			body := map[string]any{"alias": "USB", "id": "b2", "label": "New label", "ids": []any{"b2", "a1"}}
			if _, err := c.Action(context.Background(), "POST", "/api/lines/"+action, body); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(e.calls, []string{"apply"}) {
				t.Fatalf("line action stopped live routing: %v", e.calls)
			}
		})
	}
}

func TestServiceLiveUpdateFailureRetriesWithoutStopping(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.op.Engine = liveUpdateEngine{e}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range c.adapters {
		a["ipv6"] = true
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.at = clock.at.Add(30 * time.Second)
	before := e.Snapshot()
	e.calls = nil
	e.failure = errors.New("route prepare refused")
	if err := c.Supervise(context.Background()); err == nil || !strings.Contains(err.Error(), "route prepare refused") {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) || !reflect.DeepEqual(e.Snapshot(), before) {
		t.Fatal("failed apply disturbed live engine", e.calls)
	}
	e.failure = nil
	e.calls = nil
	e.beforeApply = func(r engine.Revision) {
		if !r.Policy.IPv6 {
			t.Fatal("retry lost desired IPv6")
		}
		if len(files.syncs) == 0 {
			t.Fatal("revision not synced before apply")
		}
		var desired engine.Revision
		b, err := json.Marshal(c.op.Journal.Values()["desired"])
		if err != nil || json.Unmarshal(b, &desired) != nil || !reflect.DeepEqual(desired, r) {
			t.Fatal("desired revision not durable before retry")
		}
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) || !e.Snapshot().Policy.IPv6 {
		t.Fatal("settled update was not retried immediately", e.calls)
	}
	if len(c.failureTimes) != 0 {
		t.Fatal("live apply consumed crash budget")
	}
}

func TestServiceLiveRenameReconcilesIdentityBeforeApply(t *testing.T) {
	items := testLines()
	items[1].GUID = ptr("{ABC}")
	c, e, _, _ := testCore(t, map[string]any{"lines": items})
	c.op.ServiceMode = true
	c.op.Engine = liveUpdateEngine{e}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.calls = nil
	c.adapters[1]["alias"], c.adapters[1]["guid"] = "Renamed Wi-Fi", "abc"
	if err := c.followAdapters(); err != nil {
		t.Fatal(err)
	}
	e.beforeApply = func(r engine.Revision) {
		if r.Policy.Lines[1].ID != "b2" || r.Policy.Lines[1].Alias != "Renamed Wi-Fi" {
			t.Fatal("rename changed logical identity", r.Policy.Lines)
		}
		compiled, err := engine.NativeRevision(r, apppath.Windows)
		if err != nil || compiled.Config.Lines[1].ID != "b2" || compiled.Config.Lines[1].Interface != "Renamed Wi-Fi" {
			t.Fatal("native binding did not follow alias", compiled, err)
		}
		var saved struct {
			Desired  engine.Revision `json:"desired"`
			Settings struct {
				Lines []struct{ ID, Alias string } `json:"lines"`
			} `json:"settings"`
		}
		b, err := json.Marshal(c.op.Journal.Values())
		if err != nil || json.Unmarshal(b, &saved) != nil || saved.Desired.Hash != r.Hash || saved.Settings.Lines[1].ID != "b2" || saved.Settings.Lines[1].Alias != "Renamed Wi-Fi" {
			t.Fatal("rename not durable before apply")
		}
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) {
		t.Fatal("rename replaced instance", e.calls)
	}
}

func TestServiceLiveUpdateJournalFailureKeepsOldRevision(t *testing.T) {
	c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.op.Engine = liveUpdateEngine{e}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range c.adapters {
		a["ipv6"] = true
	}
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.at = clock.at.Add(30 * time.Second)
	before := e.Snapshot()
	e.calls = nil
	files.fail = true
	if err := c.Supervise(context.Background()); err == nil || !strings.Contains(err.Error(), "not committed") {
		t.Fatal(err)
	}
	if len(e.calls) != 0 || !reflect.DeepEqual(before, e.Snapshot()) {
		t.Fatal("journal failure mutated engine", e.calls)
	}
	files.fail = false
	if err := c.Supervise(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) {
		t.Fatal("durability recovery did not retry", e.calls)
	}
}
