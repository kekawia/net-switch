package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/desktop"
	"github.com/kekawia/net-switch/internal/localipc"
)

type updateDesktopUI struct {
	*fakeDesktopUI
	visible bool
}

func (u *updateDesktopUI) WindowVisible() bool { return u.visible }

func TestUpdateDesktopRestartReleasesLockWithoutQuitOrSignIn(t *testing.T) {
	for _, visible := range []bool{false, true} {
		t.Run(fmt.Sprint(visible), func(t *testing.T) {
			var quits, signins atomic.Int32
			var acknowledged, issued atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/quit" {
					quits.Add(1)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"routing": map[string]any{"status": "on", "wanted": true}})
			}))
			defer server.Close()
			oldDial, oldUI, oldScope, oldLaunch := dialIPC, startDesktopUI, desktopScope, launchReplacementDesktop
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			finished := make(chan struct{})
			var connectionsMu sync.Mutex
			var connections []io.Closer
			t.Cleanup(func() {
				cancel()
				connectionsMu.Lock()
				for _, c := range connections {
					c.Close()
				}
				connectionsMu.Unlock()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("desktop did not finish cleanup")
					return
				}
				dialIPC, startDesktopUI, desktopScope, launchReplacementDesktop = oldDial, oldUI, oldScope, oldLaunch
			})
			ui := &updateDesktopUI{fakeDesktopUI: newFakeDesktopUI(), visible: visible}
			startDesktopUI = func(desktop.UICallbacks) desktop.UI { return ui }
			scope := fmt.Sprintf("update-restart-%d", time.Now().UnixNano())
			desktopScope = func() string { return scope }
			launched := make(chan bool, 1)
			launchReplacementDesktop = func(show bool) error {
				if !acknowledged.Load() || !ui.closed.Load() {
					return fmt.Errorf("restart ran before acknowledgement or UI close")
				}
				lock, err := desktop.AcquireSingleInstance(ctx, scope, false, func() {})
				if err != nil {
					return err
				}
				defer lock.Close()
				if lock.AlreadyRunning {
					return fmt.Errorf("old desktop still owns its single-instance lock")
				}
				launched <- show
				return nil
			}
			dialIPC = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
				client, service := net.Pipe()
				connectionsMu.Lock()
				connections = append(connections, service)
				connectionsMu.Unlock()
				go func() {
					defer service.Close()
					scan := bufio.NewScanner(service)
					for scan.Scan() {
						var request map[string]any
						if json.Unmarshal(scan.Bytes(), &request) != nil {
							return
						}
						reply := map[string]any{"id": request["id"], "result": true}
						switch request["method"] {
						case "status":
							reply["result"] = map[string]any{"owner": Owner{User: CurrentUser(), Name: "Owner"}, "routing": "on"}
						case "session":
							reply["result"] = map[string]any{"token": "update-test", "url": server.URL, "ownerName": "Owner"}
						case "signin":
							signins.Add(1)
						case "desktop-poll":
							reply["result"] = []DesktopWork{}
							if issued.CompareAndSwap(false, true) {
								reply["result"] = []DesktopWork{{ID: "restart", Operation: "restart-self"}}
							}
						case "desktop-result":
							if request["key"] == "restart" && request["value"] == true {
								acknowledged.Store(true)
							}
						}
						if json.NewEncoder(service).Encode(reply) != nil {
							return
						}
					}
				}()
				return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: CurrentUser()}}, nil
			}
			done := make(chan error, 1)
			go func() { defer close(finished); done <- ResumeDesktop(ctx, visible) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("desktop restart timed out")
			}
			select {
			case show := <-launched:
				if show != visible {
					t.Fatal("window visibility changed")
				}
			default:
				t.Fatal("replacement desktop was not launched")
			}
			if quits.Load() != 0 || signins.Load() != 0 {
				t.Fatal("restart changed routing through Quit or sign-in", quits.Load(), signins.Load())
			}
		})
	}
}

func TestUpdateIPCCommandsNeverUseThePublicStatusPipe(t *testing.T) {
	access := &Access{Owner: Owner{User: "owner"}, Tokens: NewTokens()}
	for _, method := range []string{"desktop-restart", "update-snapshot"} {
		if _, err := access.request(context.Background(), localipc.Peer{User: "stranger"}, false, "session", controlRequest{Method: method}); err == nil {
			t.Fatal("stranger accepted", method)
		}
		if _, err := access.request(context.Background(), localipc.Peer{User: "owner"}, true, "session", controlRequest{Method: method}); err == nil {
			t.Fatal("public status pipe accepted mutation", method)
		}
	}
}
