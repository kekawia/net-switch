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
		fresh, err := fixture.dial(ctx, "tcp4", fixture.target)
		if err != nil {
			t.Fatal("fresh traffic after "+label, err)
		}
		defer fresh.Close()
		reply := nativeEcho(t, fresh, "fresh-after-"+label)
		flow := controlLiveFlow(t, observer, fixture, fresh)
		if flow.Revision != desired.Number || flow.Line != mainID || flow.Lane != mainID || !flow.PhysicalSource.IsValid() {
			t.Fatal("fresh traffic did not use acknowledged policy", flow, desired.Number)
		}
		if runtime.GOOS == "linux" {
			want := fixture.seen
			if mainID != "a1" {
				want = fixture.churnSeen
			}
			if !strings.Contains(reply, want) {
				t.Fatal("external responder saw wrong egress", reply, want)
			}
		}
		t.Logf("NATIVE_CONTROL_LIVE phase=%s instance=%s held_id=%d held_revision=%d fresh_revision=%d lane=%s physical_line=%s physical_source=%s", label, observer.instance, still.ID, still.Revision, flow.Revision, flow.Lane, flow.Line, flow.PhysicalSource)
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
