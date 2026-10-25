package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
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

func TestServiceIPv6FlapsAndOtherPolicyWriters(t *testing.T) {
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	c.op.Engine = liveUpdateEngine{e}
	e.ackPoint = 1
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	set := func(v bool) {
		for _, a := range c.adapters {
			a["ipv6"] = v
		}
	}
	poll := func() {
		if err := c.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	set(true)
	poll()
	clock.advance(20000)
	set(false)
	poll() // returning to loaded value cancels the pending transition
	clock.advance(1000)
	set(true)
	poll()
	clock.advance(10000)
	// Raw input and the UI remain distinct during settlement.
	if !c.ipv6Locked() || e.Snapshot().StartedWith.IPv6 {
		t.Fatal("raw availability confused with loaded policy")
	}
	if c.State()["routing"].(map[string]any)["ipv6"] != false {
		t.Fatal("UI reports desired instead of loaded IPv6")
	}
	for _, action := range []struct {
		path string
		body map[string]any
	}{
		{"/api/app-line", map[string]any{"path": "C:\\game.exe", "line": "b2"}},
		{"/api/lines/order", map[string]any{"ids": []any{"b2", "a1"}}},
		{"/api/lines/order", map[string]any{"ids": []any{"a1", "b2"}}},
	} {
		if _, err := c.Action(context.Background(), "POST", action.path, action.body); err != nil {
			t.Fatal(err)
		}
		if e.Snapshot().Policy.IPv6 {
			t.Fatal("unrelated API bypassed settlement", action.path)
		}
	}
	// Exercise the cap transaction with a real pending closure, not just the
	// no-intent Poll path. Its atomic revision must still retain loaded IPv6.
	c.exhausted["b2"], c.closePending["b2"] = true, true
	connections := []engine.Connection{{Connection: apps.Connection{ID: "held-secondary", Chains: []string{"line-b2"}}}}
	e.connections = connections
	e.beforeApply = func(r engine.Revision) {
		if r.Policy.IPv6 {
			t.Fatal("cap transaction bypassed settlement")
		}
	}
	if err := c.closeExhausted(context.Background(), connections, c.generation); err != nil {
		t.Fatal(err)
	}
	if err := c.finishClosures(context.Background(), c.generation); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, call := range e.calls {
		found = found || call == "close:held-secondary"
	}
	if !found {
		t.Fatal("cap closure starting condition was not exercised", e.calls)
	}
	e.beforeApply = nil
	clock.advance(19999)
	poll()
	if e.Snapshot().Policy.IPv6 {
		t.Fatal("flap reused the first deadline")
	}
	clock.advance(1)
	poll()
	if !e.Snapshot().Policy.IPv6 {
		t.Fatal("other revisions reset the stable-change deadline")
	}
}

func TestServiceIPv6InstanceBookkeeping(t *testing.T) {
	for _, mode := range []string{"fresh-start", "restart", "reattach", "unknown-loaded-reply"} {
		t.Run(mode, func(t *testing.T) {
			c, e, clock, files := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			c.op.Engine = liveUpdateEngine{e}
			if mode != "fresh-start" {
				if err := c.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			for _, a := range c.adapters {
				a["ipv6"] = true
			}
			if mode == "fresh-start" || mode == "restart" {
				if mode == "restart" {
					if err := c.Poll(context.Background()); err != nil {
						t.Fatal(err)
					}
					if err := c.Routing(context.Background(), false); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Routing(context.Background(), true); err != nil {
					t.Fatal(err)
				}
				if !e.Snapshot().Policy.IPv6 {
					t.Fatal("fresh lifetime waited on old settlement")
				}
				return
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			clock.advance(20000)
			if mode == "reattach" {
				// New Control has no local timer, but receives the same loaded
				// policy from Remote's authenticated status. It starts a fresh
				// observation interval, never treats desired as loaded.
				adapters := c.adapters
				c.cancel()
				c, _, _, _ = testCoreWithFiles(t, files, clock)
				c.op.ServiceMode, c.op.Engine, c.adapters = true, liveUpdateEngine{e}, adapters
			} else {
				e.s.StartedWith = nil // Remote cannot map an unknown loaded hash
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Policy.IPv6 {
				t.Fatal("reattach/unknown reply bypassed settlement")
			}
			if mode == "reattach" {
				clock.advance(29999)
			} else {
				clock.advance(9999)
			}
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Policy.IPv6 {
				t.Fatal("policy changed before retained deadline")
			}
			clock.advance(1)
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !e.Snapshot().Policy.IPv6 {
				t.Fatal("policy did not settle")
			}
		})
	}
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

func TestServiceIPv6SettlementWithPollAndSupervisor(t *testing.T) {
	for _, initial := range []bool{false, true} {
		for _, pollFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("initial=%t/pollFirst=%t", initial, pollFirst), func(t *testing.T) {
				c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
				c.op.ServiceMode = true
				c.op.Engine = liveUpdateEngine{e}
				for _, a := range c.adapters {
					a["ipv6"] = initial
				}
				if err := c.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				e.calls = nil
				for _, a := range c.adapters {
					a["ipv6"] = !initial
				}
				tick := func() {
					first, second := c.Supervise, c.Poll
					if pollFirst {
						first, second = second, first
					}
					if err := first(context.Background()); err != nil {
						t.Fatal(err)
					}
					if err := second(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				tick()
				if e.Snapshot().Policy.IPv6 != initial {
					t.Fatal("Poll bypassed IPv6 settlement at t=0")
				}
				clock.at = clock.at.Add(29999 * time.Millisecond)
				tick()
				if e.Snapshot().Policy.IPv6 != initial {
					t.Fatal("IPv6 applied before 30 seconds")
				}
				clock.at = clock.at.Add(time.Millisecond)
				tick()
				if e.Snapshot().Policy.IPv6 == initial {
					t.Fatal("stable IPv6 not applied at 30 seconds")
				}
				for _, call := range e.calls {
					if call == "stop" || call == "start" {
						t.Fatal("settlement replaced engine", e.calls)
					}
				}
			})
		}
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
	var failed engine.Revision
	e.beforeApply = func(r engine.Revision) { failed = r }
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) || !reflect.DeepEqual(e.Snapshot(), before) {
		t.Fatal("failed Poll apply disturbed engine", e.calls)
	}
	if !strings.Contains(strings.Join(files.logs, "\n"), "route prepare refused") {
		t.Fatal("Poll hid apply error")
	}
	e.calls = nil
	if err := c.Supervise(context.Background()); err == nil || !strings.Contains(err.Error(), "route prepare refused") {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) || !reflect.DeepEqual(e.Snapshot(), before) {
		t.Fatal("failed apply disturbed live engine", e.calls)
	}
	e.failure = nil
	e.calls = nil
	e.beforeApply = func(r engine.Revision) {
		if r.Number != failed.Number || r.Hash != failed.Hash {
			t.Fatal("retry replaced settled revision", failed, r)
		}
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
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, []string{"apply"}) || !e.Snapshot().Policy.IPv6 {
		t.Fatal("settled update was not retried immediately", e.calls)
	}
	if len(c.failureTimes) != 0 {
		t.Fatal("live apply consumed crash budget")
	}
}

func TestServiceIPv6SettingUsesTheSameSettlement(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			c, e, clock, _ := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode, c.op.Engine = true, liveUpdateEngine{e}
			for _, a := range c.adapters {
				a["ipv6"] = true
			}
			setting := "auto"
			if !initial {
				setting = "off"
			}
			if err := c.save(map[string]any{"ipv6": setting}); err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Policy.IPv6 != initial {
				t.Fatal("startup ignored configured IPv6")
			}
			setting = "off"
			if !initial {
				setting = "auto"
			}
			// ipv6 is a persisted configuration input; /api/settings does not
			// expose it. Use the actual save transaction, not a fabricated API.
			if err := c.save(map[string]any{"ipv6": setting}); err != nil {
				t.Fatal(err)
			}
			if err := c.ApplyPolicy(context.Background()); err != nil {
				t.Fatal(err)
			}
			clock.advance(29999)
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Policy.IPv6 != initial {
				t.Fatal("setting bypassed settlement")
			}
			clock.advance(1)
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.Snapshot().Policy.IPv6 == initial {
				t.Fatal("setting never applied")
			}
		})
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
