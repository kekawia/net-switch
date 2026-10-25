package lifecycle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"github.com/AyoubAchour/net-switch/internal/service"
)

// Control owns the lease and all mutations. This observer reads the current
// epoch from hello; it never attaches, renews, starts, or applies a policy.
func observeNativeControl(t *testing.T, ctx context.Context) *nativeClient {
	t.Helper()
	conn, err := localipc.DialNativeEngine(ctx, localipc.Endpoint{Path: localipc.DefaultPath("engine"), Kind: "engine", Service: service.Engine})
	if err != nil {
		t.Fatal(err)
	}
	rpc := lifecycle.NewRPC(conn)
	t.Cleanup(func() { rpc.Close() })
	var hello struct {
		Instance string `json:"engineInstanceId"`
		Epoch    uint64 `json:"epoch"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "hello"}, &hello); err != nil || hello.Instance == "" || hello.Epoch == 0 {
		t.Fatal("observer hello", hello, err)
	}
	return &nativeClient{rpc: rpc, instance: hello.Instance, epoch: hello.Epoch}
}

func controlDesired(t *testing.T, data string) ce.Revision {
	t.Helper()
	var j struct {
		Desired ce.Revision `json:"desired"`
	}
	if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &j); err != nil {
		t.Fatal(err)
	}
	return j.Desired
}

type controlPolicyWitness struct {
	desired  ce.Revision
	status   protocol.Status
	instance string // Control journal's engineInstanceId
}

func (w controlPolicyWitness) validate(instance, mainID, alias string, initialAck uint64) error {
	p := w.desired.Policy
	if w.instance != instance || w.desired.Number < initialAck || len(p.Lines) == 0 || p.Lines[0].ID != mainID || p.Lines[0].Alias != alias {
		return fmt.Errorf("witness predates action or has wrong main binding: %+v", w.desired)
	}
	native, err := lifecycle.NativeRevision(w.desired)
	if err != nil {
		return err
	}
	s := w.status
	if s.State != "on" || s.Instance != instance || s.Applied == nil || s.Applied.N != native.N || s.Applied.Hash != native.Hash || s.Applied.Point == 0 {
		return fmt.Errorf("journal and loaded native policy do not match: desired=%+v status=%+v", w.desired, s)
	}
	return nil
}

// Two exact snapshots bracket one fresh admission. Never retry traffic or
// infer an intermediate config from a newer revision counter.
func chooseControlPolicyWitness(before, after controlPolicyWitness, flow flows.Record, instance, mainID, alias string, initialAck uint64) (controlPolicyWitness, string, error) {
	for _, w := range []controlPolicyWitness{before, after} {
		if err := w.validate(instance, mainID, alias, initialAck); err != nil {
			return controlPolicyWitness{}, "", err
		}
	}
	if after.desired.Number < before.desired.Number || after.status.Applied.Point < before.status.Applied.Point ||
		(after.desired.Number > before.desired.Number && after.status.Applied.Point == before.status.Applied.Point) ||
		(after.desired.Number == before.desired.Number && (after.status.Applied.Hash != before.status.Applied.Hash || after.status.Applied.Point != before.status.Applied.Point)) {
		return controlPolicyWitness{}, "", fmt.Errorf("inconsistent before/after policy witnesses")
	}
	w := before
	if flow.Revision != before.desired.Number {
		if flow.Revision != after.desired.Number {
			return controlPolicyWitness{}, "", fmt.Errorf("flow revision %d was not witnessed (before=%d after=%d initial=%d)", flow.Revision, before.desired.Number, after.desired.Number, initialAck)
		}
		w = after
	}
	target := w.desired.Policy.Lanes[mainID]
	if target == "" {
		target = mainID
	}
	if flow.Lane != mainID || flow.Line != target || !flow.PhysicalSource.IsValid() {
		return controlPolicyWitness{}, "", fmt.Errorf("flow disagrees with exact witnessed routing: flow=%+v target=%s", flow, target)
	}
	for _, line := range w.desired.Policy.Lines {
		if line.ID == target {
			return w, line.Alias, nil
		}
	}
	return controlPolicyWitness{}, "", fmt.Errorf("witness has no physical target %s", target)
}

func controlLiveFlow(t *testing.T, observer *nativeClient, fixture tunFixture, conn net.Conn) flows.Record {
	t.Helper()
	_, source := fixture.origin(t, conn)
	destination := netip.MustParseAddrPort(fixture.target)
	same := func(a, b netip.AddrPort) bool { return a.Addr().Unmap() == b.Addr().Unmap() && a.Port() == b.Port() }
	cursor := ""
	seen := map[string]bool{}
	for {
		var page flows.Page
		nativeMust(t, observer, "flows", map[string]any{"cursor": cursor}, &page)
		for _, flow := range page.Flows {
			if flow.Protocol == "tcp" && same(flow.Source, source) && same(flow.Destination, destination) {
				return flow
			}
		}
		if page.Cursor == "" || seen[page.Cursor] {
			t.Fatal("held echo missing from native flows", source, destination)
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
}

func nativeControlLiveUpdates(t *testing.T, ctx context.Context, c *client, owner actor, fixture tunFixture, data string) {
	t.Helper()
	observer := observeNativeControl(t, ctx)
	held, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	nativeEcho(t, held, "held-before-control-live-update")
	original := controlLiveFlow(t, observer, fixture, held)
	if original.Line != "a1" || original.Lane != "a1" || original.Revision == 0 || !original.PhysicalSource.IsValid() {
		t.Fatal("held flow starting condition", original)
	}
	var session struct{ URL, Token string }
	c.must(t, "session", nil, &session)
	action := func(path string, body any) {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if code, result := apiAs(t, owner, session.URL, session.Token, "POST", path, string(b)); code != 200 {
			t.Fatalf("%s: %d %s", path, code, result)
		}
	}
	verify := func(label, mainID, alias string, after uint64) {
		var desired ce.Revision
		wait(t, "Control acknowledged "+label, 30*time.Second, func() bool {
			desired = controlDesired(t, data)
			if desired.Number <= after || len(desired.Policy.Lines) == 0 || desired.Policy.Lines[0].ID != mainID || desired.Policy.Lines[0].Alias != alias {
				return false
			}
			native, err := lifecycle.NativeRevision(desired)
			if err != nil {
				t.Fatal(err)
			}
			var status protocol.Status
			nativeMust(t, observer, "status", nil, &status)
			return status.State == "on" && status.Instance == observer.instance && status.Applied != nil && status.Applied.N == native.N && status.Applied.Hash == native.Hash && status.Applied.Point != 0
		})
		initialAck := desired.Number
		// Keep the installed product loops running across several poll and
		// supervisor rounds; a delayed restart must fail the held exchange too.
		for range 4 {
			nativeEcho(t, held, "held-through-"+label)
			time.Sleep(time.Second)
		}
		if s := getStatus(t, c); s.Instance != observer.instance || s.Routing != "on" {
			t.Fatal("Control replaced live engine", s)
		}
		still := controlLiveFlow(t, observer, fixture, held)
		if still.ID != original.ID || still.Revision != original.Revision || still.Line != original.Line || still.PhysicalSource != original.PhysicalSource {
			t.Fatal("held flow changed identity or physical source", original, still)
		}
		capture := func() controlPolicyWitness {
			var j struct {
				Desired  ce.Revision `json:"desired"`
				Instance string      `json:"engineInstanceId"`
			}
			if err := lifecycle.Read(filepath.Join(data, "control-journal.json"), &j); err != nil {
				t.Fatal(err)
			}
			w := controlPolicyWitness{desired: j.Desired, instance: j.Instance}
			nativeMust(t, observer, "status", nil, &w.status)
			return w
		}
		beforeAdmission := capture()
		fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
		if err != nil {
			t.Fatal("fresh traffic after "+label, err)
		}
		defer fresh.Close()
		reply := nativeEcho(t, fresh, "fresh-after-"+label)
		afterAdmission := capture()
		flow := controlLiveFlow(t, observer, fixture, fresh)
		t.Logf("NATIVE_CONTROL_LIVE_WITNESSES phase=%s initial_ack=%d before=%+v after=%+v raw_flow=%+v", label, initialAck, beforeAdmission, afterAdmission, flow)
		witness, physicalAlias, err := chooseControlPolicyWitness(beforeAdmission, afterAdmission, flow, observer.instance, mainID, alias, initialAck)
		if err != nil {
			t.Fatal("fresh traffic did not use an exactly witnessed acknowledged policy", err)
		}
		t.Logf("NATIVE_CONTROL_LIVE_CHOSEN initial_ack=%d chosen_revision=%d native_hash=%s apply_point=%d instance=%s", initialAck, witness.desired.Number, witness.status.Applied.Hash, witness.status.Applied.Point, witness.instance)
		if runtime.GOOS == "linux" {
			var want string
			switch physicalAlias {
			case fixture.line:
				want = fixture.seen
			case fixture.churnLine:
				want = fixture.churnSeen
			default:
				t.Fatal("no external egress mapping for witnessed physical alias", physicalAlias)
			}
			if want == "" || !strings.Contains(reply, want) {
				t.Fatal("external responder saw wrong egress", reply, want)
			}
		}
		t.Logf("NATIVE_CONTROL_LIVE phase=%s instance=%s held_id=%d held_revision=%d initial_ack=%d chosen_witness=%d fresh_revision=%d lane=%s physical_line=%s physical_alias=%s physical_source=%s", label, observer.instance, still.ID, still.Revision, initialAck, witness.desired.Number, flow.Revision, flow.Lane, flow.Line, physicalAlias, flow.PhysicalSource)
	}
	if runtime.GOOS == "windows" {
		// Let the real adapter reader acquire the stable GUID before renaming.
		wait(t, "Control learned adapter GUID", 30*time.Second, func() bool {
			p := controlDesired(t, data).Policy
			return len(p.Lines) == 1 && p.Lines[0].GUID != nil && *p.Lines[0].GUID != ""
		})
		rename := func(from, to string) error {
			script := fmt.Sprintf("Rename-NetAdapter -Name '%s' -NewName '%s' -ErrorAction Stop", strings.ReplaceAll(from, "'", "''"), strings.ReplaceAll(to, "'", "''"))
			out, err := exec.CommandContext(ctx, "pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
			if err != nil {
				return fmt.Errorf("rename: %w: %s", err, out)
			}
			return nil
		}
		before := controlDesired(t, data).Number
		const renamed = "NS-Live-Renamed"
		if err := rename(fixture.line, renamed); err != nil {
			t.Fatal(err)
		}
		restoreNeeded := true
		defer func() {
			if restoreNeeded {
				if err := rename(renamed, fixture.line); err != nil {
					t.Error(err)
				}
			}
		}()
		verify("adapter-rename", "a1", renamed, before)
		before = controlDesired(t, data).Number
		if err := rename(renamed, fixture.line); err != nil {
			t.Fatal(err)
		}
		restoreNeeded = false
		verify("adapter-rename-back", "a1", fixture.line, before)
		return
	}
	// Linux's reader exposes interface names, not stable rename IDs. Exercise
	// the supported line API against the fixture's two independent real paths.
	before := controlDesired(t, data).Number
	action("/api/lines/add", map[string]any{"alias": fixture.churnLine})
	verify("line-add", "a1", fixture.line, before)
	p := controlDesired(t, data)
	if len(p.Policy.Lines) != 2 {
		t.Fatal("second physical line was not added", p)
	}
	second := p.Policy.Lines[1].ID
	action("/api/lines/order", map[string]any{"ids": []string{second, "a1"}})
	verify("line-order", second, fixture.churnLine, p.Number)
	before = controlDesired(t, data).Number
	action("/api/lines/remove", map[string]any{"id": second})
	verify("line-remove", "a1", fixture.line, before)
}
