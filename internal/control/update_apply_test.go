package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	js "github.com/kekawia/net-switch/internal/jsvalue"
	"github.com/kekawia/net-switch/internal/updates"
)

type fakeUpdateBackend struct {
	status     *updates.Status
	starts     []string
	dismissals []string
}

func (f *fakeUpdateBackend) Start(_ context.Context, version string) error {
	f.starts = append(f.starts, version)
	f.status = &updates.Status{Operation: "operation", Phase: "downloading", Version: version}
	return nil
}
func (f *fakeUpdateBackend) Status() *updates.Status {
	if f.status == nil {
		return nil
	}
	copy := *f.status
	return &copy
}
func (f *fakeUpdateBackend) Dismiss(operation string) error {
	f.dismissals = append(f.dismissals, operation)
	f.status = nil
	return nil
}

func TestUpdateApplyHTTPAuthenticatesAndAcceptsOnlyTheOfferedVersion(t *testing.T) {
	c, _, _, _ := testCore(t, map[string]any{})
	backend := &fakeUpdateBackend{}
	c.op.Updater = backend
	c.offer = &updates.Offer{Version: "1.1.0", Installer: updates.InstallerURL("1.1.0", "x64")}
	handler := &HTTP{Core: c, Port: 9527, Token: "test-token"}
	request := func(path, token, origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9527"+path, strings.NewReader(body))
		r.Header.Set("X-Token", token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("/api/update/apply", "wrong", "", `{"version":"1.1.0"}`); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("/api/update/apply", "test-token", "https://example.com", `{"version":"1.1.0"}`); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("/api/update/apply", "test-token", "", `{"version":"0.9.0"}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if len(backend.starts) != 0 {
		t.Fatal("refused request started an update")
	}
	w := request("/api/update/apply", "test-token", "", `{"version":"1.1.0","installer":"C:/untrusted.exe","url":"https://example.com/untrusted.exe"}`)
	if w.Code != 200 || len(backend.starts) != 1 || backend.starts[0] != "1.1.0" {
		t.Fatal(w.Code, w.Body.String(), backend.starts)
	}
	var response map[string]any
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || js.Object(response["updateStatus"])["phase"] != "downloading" {
		t.Fatal(w.Body.String())
	}
	if w := request("/api/update/status-dismiss", "test-token", "", `{"operation":"operation"}`); w.Code != 400 {
		t.Fatal("busy update dismissed", w.Code)
	}
	backend.status.Phase = "rolled-back"
	c.offer = nil // a restarted Control has not checked GitHub yet
	if w := request("/api/update/apply", "test-token", "", `{"version":"1.1.0"}`); w.Code != 200 {
		t.Fatal("rollback retry required a stale in-memory offer", w.Body.String())
	}
	backend.status.Phase = "signature-error"
	if w := request("/api/update/status-dismiss", "test-token", "", `{"operation":"stale"}`); w.Code != 400 {
		t.Fatal("stale dismissal accepted")
	}
	if w := request("/api/update/status-dismiss", "test-token", "", `{"operation":"operation"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if _, exists := c.State()["updateStatus"]; exists {
		t.Fatal("absent update state changed the old state contract")
	}
}

func TestUpdateServiceStopPreservesLatestOwnerRoutingChoice(t *testing.T) {
	for _, explicitStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "still-on", true: "owner-stopped"}[explicitStop], func(t *testing.T) {
			c, _, clock, files := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			backend := &fakeUpdateBackend{status: &updates.Status{Operation: "update-one", Phase: "downloading", Version: "1.1.0"}}
			c.op.Updater = backend
			if err := c.Routing(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			backend.status.Phase = "preparing"
			if explicitStop {
				if _, err := c.Action(context.Background(), "POST", "/api/routing", map[string]any{"on": false}); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.ShutdownForService(context.Background()); err != nil {
				t.Fatal(err)
			}
			intent := js.Object(c.op.Journal.Values()["updateIntent"])
			if intent["operation"] != "update-one" || intent["wanted"] != !explicitStop || c.op.Journal.Values()["wanted"] != false {
				t.Fatal("service stop lost owner choice", intent)
			}
			restarted, engine, _, _ := testCoreWithFilesMode(t, files, clock, true)
			restarted.op.Updater = backend
			if err := restarted.RestoreUpdateIntent("update-one", true); err != nil {
				t.Fatal(err)
			}
			if restarted.WantsRouting() != !explicitStop {
				t.Fatal("restart reversed owner choice")
			}
			if err := restarted.ResumeRouting(context.Background()); err != nil {
				t.Fatal(err)
			}
			if explicitStop && engine.Snapshot().Status == "on" {
				t.Fatal("update turned routing on after an explicit stop")
			}
		})
	}
}

func TestUpdateIntentAndOwnerStopFailAtomically(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	c.op.ServiceMode = true
	backend := &fakeUpdateBackend{status: &updates.Status{Operation: "update-one", Phase: "downloading", Version: "1.1.0"}}
	c.op.Updater = backend
	if err := c.Routing(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	backend.status.Phase = "applying"
	files.fail = true
	if err := c.Routing(context.Background(), false); err == nil {
		t.Fatal("failed stop commit was accepted")
	}
	if !c.WantsRouting() || js.Object(c.op.Journal.Values()["updateIntent"])["wanted"] != true {
		t.Fatal("refused stop changed either routing choice")
	}
	files.fail = false
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if js.Object(c.op.Journal.Values()["updateIntent"])["wanted"] != false {
		t.Fatal("Quit did not override the update's earlier choice")
	}
}
