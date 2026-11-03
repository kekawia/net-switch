package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

// End to end inside Control: a tracked sandbox app carries the engine's
// identity, the pin API stores that identity, the revision carries it, and the
// state shows the identity; a stale path pin is kept, shown and flagged.
func TestPinFromTrackedSandboxAppStoresTheEngineIdentity(t *testing.T) {
	c, e, _, _ := testCore(t, map[string]any{"lines": testLines()})
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	flow := engine.Connection{}
	flow.ID = "1"
	flow.Metadata.ProcessPath = "/snap/foo/123/bin/foo"
	flow.AppID = "snap:foo"
	flow.Chains = []string{"line-a1"}
	flow.Start = c.op.Clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	e.connections = []engine.Connection{flow}
	if err := c.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.tracker.IdentityOf(apps.AppKey("/snap/foo/123/bin/foo")); got != "snap:foo" {
		t.Fatal("tracked app lost the engine identity", got)
	}
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/snap/foo/123/bin/foo", "line": "b2"}); err != nil {
		t.Fatal(err)
	}
	pins := c.pinsLocked()
	if len(pins) != 1 || pins[0].Path != "snap:foo" || pins[0].LineID != "b2" {
		t.Fatalf("pin did not store the selected identity: %+v", pins)
	}
	if p := e.Snapshot().Policy.AppLines; len(p) != 1 || p[0].Path != "snap:foo" {
		t.Fatalf("revision did not carry the identity pin: %+v", p)
	}
	state := stateRows(t, c)
	row := state[apps.AppKey("/snap/foo/123/bin/foo")]
	if row == nil || row["identity"] != "snap:foo" || js.Text(row["line"]) != "b2" || row["pinNeedsReselection"] != nil {
		t.Fatalf("state row for the tracked snap: %+v", row)
	}
	// Repinning or unpinning through the path replaces that identity pin.
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/snap/foo/123/bin/foo", "line": nil}); err != nil {
		t.Fatal(err)
	}
	if len(c.pinsLocked()) != 0 {
		t.Fatalf("identity pin survived unpinning by path: %+v", c.pinsLocked())
	}
	// A path pin stored for a sandboxed app (never written by this code; it
	// could only predate it) is kept and shown as needing reselection.
	if err := c.save(map[string]any{"appLines": apps.Pins{{Path: "/snap/foo/123/bin/foo", LineID: "b2"}}}); err != nil {
		t.Fatal(err)
	}
	row = stateRows(t, c)[apps.AppKey("/snap/foo/123/bin/foo")]
	if row == nil || row["pinNeedsReselection"] != true || js.Text(row["line"]) != "b2" {
		t.Fatalf("stale sandbox path pin not flagged: %+v", row)
	}
	// Windows and plain rows keep their shape: no identity, no flag.
	if plain := stateRows(t, c)[apps.AppKey(`C:\Apps\Main.exe`)]; plain != nil {
		t.Fatal("unexpected row", plain)
	}
}

func testLinuxCore(t *testing.T, initial map[string]any) (*Core, *fakeEngine, *fakePlatform, *memoryFiles) {
	t.Helper()
	files := &memoryFiles{data: map[string][]byte{}}
	b, err := js.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	files.data[filepath.Join("/test", "settings.json")] = b
	clock := &fakeClock{at: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	var serial atomic.Uint64
	id := func() string { return fmt.Sprintf("%012x", serial.Add(1)) }
	io := settings.Options{Files: files, Now: clock.Now, ID: id, Sleep: func(time.Duration) {}}
	store := settings.New("/test", io)
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	journal := io
	journal.FileName = "control-journal.json"
	journal.Defaults = map[string]any{"revision": float64(0), "closures": []any{}}
	j := settings.New("/test", journal)
	if _, err := j.Load(); err != nil {
		t.Fatal(err)
	}
	undo := io
	undo.FileName = "windows-undo.json"
	undo.Defaults = map[string]any{"metrics": map[string]any{}, "policy": map[string]any{}}
	u := settings.New("/test", undo)
	if _, err := u.Load(); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{s: engine.Snapshot{Status: "off", Instance: "linux-engine", Policy: engine.Policy{}}}
	p := &fakePlatform{recordClose: func(v any) {
		raw, _ := js.Marshal(v)
		decoded, _ := js.Decode(raw)
		files.outsideCloses = append(files.outsideCloses, decoded)
	}}
	rules := apppath.Linux
	c, err := New(context.Background(), Options{
		ServiceMode: true,
		PathRules:   &rules,
		Engine:      f,
		Platform:    p,
		Settings:    store,
		Undo:        u,
		Journal:     j,
		IO:          io,
		Clock:       clock,
		Location:    time.UTC,
		Mode:        "tun",
		Version:     "1.0.0",
		UserDir:     "/test",
		ID:          id,
		LineID:      func() string { return fmt.Sprintf("%06x", serial.Add(1)) },
		Background:  func(fn func()) { fn() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.cancel)
	c.elevated = true
	for i, line := range c.itemsLocked() {
		address := fmt.Sprintf("192.0.2.%d", i+1)
		c.adapters = append(c.adapters, map[string]any{"alias": line.Alias, "ipv4s": []any{address}, "connected": true})
		c.routes = append(c.routes, map[string]any{"interfaceAddress": address})
	}
	c.routesAt = c.now()
	c.routesSequence = c.networkIssued.Add(1)
	return c, f, p, files
}

func TestLinuxRowsKeyByEngineIdentityAndNeverCollideOnSharedPaths(t *testing.T) {
	c, e, p, files := testLinuxCore(t, map[string]any{"lines": testLines()})
	iconOne := base64.StdEncoding.EncodeToString([]byte("png-one"))
	iconTwo := base64.StdEncoding.EncodeToString([]byte("png-two"))
	p.override = func(name string, a map[string]any) (any, error, bool) {
		if name != "app-info" {
			return nil, nil, false
		}
		out := []any{}
		paths, _ := a["paths"].([]string)
		for _, raw := range paths {
			switch raw {
			case "flatpak:org.one.Game":
				out = append(out, map[string]any{"identity": "flatpak:org.one.Game", "path": "/app/bin/game", "name": "Game One", "icon": iconOne})
			case "flatpak:org.two.Game":
				out = append(out, map[string]any{"identity": "flatpak:org.two.Game", "path": "/app/bin/game", "name": "Game Two", "icon": iconTwo})
			}
		}
		return out, nil, true
	}

	ctx := context.Background()
	if err := c.Routing(ctx, true); err != nil {
		t.Fatal(err)
	}
	start := c.op.Clock.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	makeFlow := func(id, path, appID, line string) engine.Connection {
		var f engine.Connection
		f.ID = id
		f.Metadata.ProcessPath = path
		f.AppID = appID
		f.Chains = []string{"line-" + line}
		f.Start = start
		return f
	}
	e.connections = []engine.Connection{
		makeFlow("f1", "/app/bin/game", "flatpak:org.one.Game", "a1"),
		makeFlow("f2", "/app/bin/game", "flatpak:org.two.Game", "a1"),
		makeFlow("c1", "/opt/Game/Game", "/opt/Game/Game", "a1"),
		makeFlow("c2", "/opt/game/game", "/opt/game/game", "a1"),
		makeFlow("v1", "/opt/tool/1.2.0/bin/tool", "/opt/tool/*/bin/tool", "a1"),
	}
	if err := c.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	outsideLine, _ := json.Marshal(map[string]any{
		"estats": true,
		"outside": []any{
			map[string]any{"id": "192.0.2.1:41001>198.51.100.10:443|501|2026-10-19T11:59:00Z", "pid": 501, "path": "/app/bin/game", "appId": "flatpak:org.one.Game", "local": "192.0.2.1", "created": "2026-10-19T11:59:00Z", "processStarted": "10:1"},
			map[string]any{"id": "192.0.2.1:41002>198.51.100.10:443|502|2026-10-19T11:59:00Z", "pid": 502, "path": "/app/bin/game", "appId": "flatpak:org.two.Game", "local": "192.0.2.1", "created": "2026-10-19T11:59:00Z", "processStarted": "20:2"},
		},
	})
	c.HelperLine(outsideLine)

	rows := stateRows(t, c)
	r1, r2 := rows["flatpak:org.one.Game"], rows["flatpak:org.two.Game"]
	if r1 == nil || r2 == nil {
		t.Fatalf("shared-path Flatpaks did not stay distinct rows: %+v", rows)
	}
	if r1["identity"] != "flatpak:org.one.Game" || r2["identity"] != "flatpak:org.two.Game" || r1["name"] != "Game One" || r2["name"] != "Game Two" {
		t.Fatalf("Flatpak row metadata collided: one=%+v two=%+v", r1, r2)
	}

	// Each sandbox row serves its own icon by exact key.
	handler := &HTTP{Core: c, Port: 47821, Token: "tok", ValidToken: func(s string) bool { return s == "tok" }}
	req := httptest.NewRequest("GET", "http://127.0.0.1:47821/api/icon?key=flatpak%3Aorg.two.Game", nil)
	req.Header.Set("X-Token", "tok")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "png-two" {
		t.Fatalf("icon lookup by sandbox key: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Control refuses to guess a sandbox identity from a shared executable path.
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/app/bin/game", "line": "b2"}); err == nil {
		t.Fatal("shared sandbox path pin was accepted on Linux")
	}

	// Pinning by identity pins only the chosen Flatpak; case-distinct and versioned Linux paths stay independent.
	for _, call := range [][2]string{
		{"flatpak:org.one.Game", "b2"},
		{"/opt/Game/Game", "b2"},
		{"/opt/game/game", "a1"},
		{"/opt/tool/1.3.0/bin/tool", "b2"},
	} {
		if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": call[0], "line": call[1]}); err != nil {
			t.Fatalf("pin %v: %v", call, err)
		}
	}
	rows = stateRows(t, c)
	if js.Text(rows["flatpak:org.one.Game"]["line"]) != "b2" || rows["flatpak:org.two.Game"]["line"] != nil {
		t.Fatalf("pinning one Flatpak affected the other: one=%+v two=%+v", rows["flatpak:org.one.Game"], rows["flatpak:org.two.Game"])
	}
	if js.Text(rows["/opt/Game/Game"]["line"]) != "b2" || js.Text(rows["/opt/game/game"]["line"]) != "a1" {
		t.Fatalf("case-distinct Linux rows collapsed: upper=%+v lower=%+v", rows["/opt/Game/Game"], rows["/opt/game/game"])
	}
	if js.Text(rows["/opt/tool/*/bin/tool"]["line"]) != "b2" {
		t.Fatalf("versioned Linux path did not match upgraded pin: %+v", rows["/opt/tool/*/bin/tool"])
	}

	// Reconnect on Game One closes only Game One's off-line routed and outside connections.
	e.calls = nil
	files.outsideCloses = nil
	if _, err := c.Action(ctx, "POST", "/api/reconnect", map[string]any{"key": "flatpak:org.one.Game"}); err != nil {
		t.Fatal(err)
	}
	if len(e.calls) != 1 || e.calls[0] != "close:f1" {
		t.Fatalf("routed reconnect closed wrong flows: %v", e.calls)
	}
	if len(files.outsideCloses) != 1 {
		t.Fatalf("outside reconnect calls: %+v", files.outsideCloses)
	}
	closedOutside := array(files.outsideCloses[0])
	if len(closedOutside) != 1 || js.Number(js.Object(closedOutside[0])["pid"]) != 501 {
		t.Fatalf("outside reconnect closed wrong sandbox process: %+v", closedOutside)
	}

	// A pre-existing raw sandbox path pin is flagged for reselection and can still be cleared.
	if err := c.save(map[string]any{"appLines": apps.Pins{{Path: "/snap/foo/123/bin/foo", LineID: "b2"}}}); err != nil {
		t.Fatal(err)
	}
	stale := stateRows(t, c)["/snap/foo/123/bin/foo"]
	if stale == nil || stale["pinNeedsReselection"] != true || js.Text(stale["line"]) != "b2" {
		t.Fatalf("stale Linux sandbox path pin not flagged: %+v", stale)
	}
	if _, err := c.Action(ctx, "POST", "/api/app-line", map[string]any{"path": "/snap/foo/123/bin/foo", "line": nil}); err != nil {
		t.Fatalf("clearing stale sandbox path pin failed: %v", err)
	}
	if stateRows(t, c)["/snap/foo/123/bin/foo"] != nil {
		t.Fatal("cleared stale sandbox path pin remained in state")
	}
}

func stateRows(t *testing.T, c *Core) map[string]map[string]any {
	t.Helper()
	b, err := json.Marshal(c.State())
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, row := range state.Apps {
		out[js.Text(row["key"])] = row
	}
	return out
}
