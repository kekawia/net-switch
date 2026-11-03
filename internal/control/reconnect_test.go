package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
)

func TestReconnectPersistsItsOriginalSelectionBeforeClose(t *testing.T) {
	path := `C:\Apps\Firefox.exe`
	c, e, clock, _ := testCore(t, map[string]any{"lines": testLines(), "appLines": apps.Pins{{Path: path, LineID: "b2"}}})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	connection := engine.Connection{Connection: apps.Connection{ID: "old", Start: clock.Now().Add(-time.Minute).Format(time.RFC3339Nano), Chains: []string{"line-a1"}, Download: 100}}
	connection.Metadata.ProcessPath = path
	e.connections = []engine.Connection{connection}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var first engine.CloseRequest
	e.beforeClose = func(r engine.CloseRequest) error {
		intents, err := c.pendingClosures()
		if err != nil || len(intents) != 1 || intents[0].Purpose != "reconnect" || !reflect.DeepEqual(intents[0].Request, r) {
			t.Fatalf("close preceded persisted selection: %+v %v", intents, err)
		}
		first = r
		return errors.New("lost response")
	}
	result, err := c.reconnect(context.Background(), apps.AppKey(path))
	if err != nil || result["failed"] != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	if first.StartedBefore.IsZero() || !reflect.DeepEqual(first.ConnectionIDs, []string{"old"}) {
		t.Fatal(first)
	}
	clock.advance(30000)
	connection.ID = "new"
	e.connections = append(e.connections, connection)
	e.beforeClose = func(r engine.CloseRequest) error {
		if !reflect.DeepEqual(r, first) {
			t.Fatalf("retry widened selection: %+v != %+v", r, first)
		}
		return nil
	}
	if err := c.ReplayClosures(context.Background()); err != nil {
		t.Fatal(err)
	}
	remaining, err := c.pendingClosures()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("closure not acknowledged: %+v %v", remaining, err)
	}
}

func TestReconnectSurfacesUnsupportedOutsideClosureReason(t *testing.T) {
	path := "/usr/bin/curl"
	c, _, _, _ := testCore(t, map[string]any{"lines": testLines(), "appLines": apps.Pins{{Path: path, LineID: "b2"}}})
	p := c.op.Platform.(*fakePlatform)
	p.network = map[string]any{
		"adapters": []any{
			map[string]any{"alias": "Ethernet", "name": "Ethernet", "index": float64(1), "ipv4s": []any{"192.0.2.1"}, "ipv6": false, "status": "Up", "mediaType": "Ethernet", "gateway": "192.0.2.254"},
			map[string]any{"alias": "Wi-Fi", "name": "Wi-Fi", "index": float64(2), "ipv4s": []any{"192.0.2.2"}, "ipv6": false, "status": "Up", "mediaType": "Wireless", "gateway": "192.0.2.254"},
		},
		"defaultRoutes": []any{
			map[string]any{"interfaceAddress": "192.0.2.1", "alias": "Ethernet", "index": float64(1)},
			map[string]any{"interfaceAddress": "192.0.2.2", "alias": "Wi-Fi", "index": float64(2)},
		},
		"readAt": float64(c.now()),
	}
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	helper := `{"estats":true,"outside":[{"id":"192.0.2.1:41001>198.51.100.10:443|42|2026-10-19T11:00:00.0000000Z","pid":42,"path":"/usr/bin/curl","local":"192.0.2.1","created":"2026-10-19T11:00:00.0000000Z","processStarted":"777:101","down":100,"up":20}]}`
	if !c.HelperLine([]byte(helper)) {
		t.Fatal("HelperLine rejected valid outside payload")
	}

	normalAny, err := c.Action(context.Background(), "POST", "/api/reconnect", map[string]any{"key": apps.AppKey(path)})
	if err != nil {
		t.Fatal(err)
	}
	normal := normalAny.(map[string]any)
	if _, hasReason := normal["reason"]; hasReason || normal["closed"] != 1 || normal["failed"] != 0 {
		t.Fatalf("normal reconnect response: %+v", normal)
	}

	p.override = func(name string, a map[string]any) (any, error, bool) {
		if name != "close-tcp" {
			return nil, nil, false
		}
		return map[string]any{
			"closed": float64(0),
			"failed": float64(1),
			"gone":   float64(0),
			"codes":  []any{"not supported here"},
			"reason": "not supported here",
		}, nil, true
	}
	unsupportedAny, err := c.Action(context.Background(), "POST", "/api/reconnect", map[string]any{"key": apps.AppKey(path)})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := unsupportedAny.(map[string]any)
	if unsupported["reason"] != "not supported here" || unsupported["closed"] != 0 || unsupported["failed"] != 1 || unsupported["gone"] != 0 || unsupported["state"] == nil {
		t.Fatalf("unsupported reconnect response: %+v", unsupported)
	}
}
