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

	"github.com/AyoubAchour/net-switch/internal/desktop"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

type recordedState struct {
	raw       map[string]any
	reachable bool
}

type fakeDesktopUI struct {
	mu           sync.Mutex
	sessionURL   string
	sessionToken string
	sessionOwner string
	shows        chan string
	states       chan recordedState
	quitting     chan struct{}
	quitOnce     sync.Once
	closed       atomic.Bool
}

func newFakeDesktopUI() *fakeDesktopUI {
	return &fakeDesktopUI{
		shows:    make(chan string, 16),
		states:   make(chan recordedState, 32),
		quitting: make(chan struct{}),
	}
}

func (f *fakeDesktopUI) SetSession(baseURL, token, owner string) {
	f.mu.Lock()
	f.sessionURL = baseURL
	f.sessionToken = token
	f.sessionOwner = owner
	f.mu.Unlock()
}

func (f *fakeDesktopUI) ShowWindow(appKey string) {
	select {
	case f.shows <- appKey:
	default:
	}
}

func (f *fakeDesktopUI) UpdateState(raw map[string]any, reachable bool) {
	select {
	case f.states <- recordedState{raw: raw, reachable: reachable}:
	default:
	}
}

func (f *fakeDesktopUI) SetActionFeedback(string, string) {}

func (f *fakeDesktopUI) SetQuitting() {
	f.quitOnce.Do(func() { close(f.quitting) })
}

func (f *fakeDesktopUI) Notify(string, string, bool) {}

func (f *fakeDesktopUI) Close() {
	f.closed.Store(true)
}

func serveMockDesktopIPC(t *testing.T, conn io.ReadWriteCloser, sessionFn func(call int) map[string]any) {
	t.Helper()
	defer conn.Close()
	scan := bufio.NewScanner(conn)
	var sessionCalls int
	for scan.Scan() {
		var req map[string]any
		if err := json.Unmarshal(scan.Bytes(), &req); err != nil {
			t.Error(err)
			return
		}
		reply := map[string]any{"id": req["id"]}
		switch req["method"] {
		case "status":
			reply["result"] = map[string]any{
				"owner":   Owner{User: CurrentUser(), Name: "Owner"},
				"routing": "off",
			}
		case "signin":
			reply["result"] = nil
		case "session":
			sessionCalls++
			reply["result"] = sessionFn(sessionCalls)
		case "desktop-connect":
			reply["result"] = nil
		case "desktop-poll":
			reply["result"] = []any{}
		default:
			reply["error"] = "unexpected method"
		}
		b, _ := json.Marshal(reply)
		if _, err := conn.Write(append(b, '\n')); err != nil {
			return
		}
	}
}

func TestDesktopSingleInstanceForwardsShow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/state" {
			_ = json.NewEncoder(w).Encode(map[string]any{"routing": "off"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	oldDial, oldScope, oldStartUI, oldInterval := dialIPC, desktopScope, startDesktopUI, desktopStateInterval
	t.Cleanup(func() {
		dialIPC = oldDial
		desktopScope = oldScope
		startDesktopUI = oldStartUI
		desktopStateInterval = oldInterval
	})

	scope := fmt.Sprintf("single-%d", time.Now().UnixNano())
	desktopScope = func() string { return scope }
	desktopStateInterval = 20 * time.Millisecond

	ui := newFakeDesktopUI()
	var uiStarts atomic.Int32
	startDesktopUI = func(cb desktop.UICallbacks) desktop.UI {
		uiStarts.Add(1)
		return ui
	}
	dialIPC = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		client, server := net.Pipe()
		go serveMockDesktopIPC(t, server, func(int) map[string]any {
			return map[string]any{"token": "tok-1", "url": srv.URL, "ownerName": "Owner"}
		})
		return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: CurrentUser()}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Desktop(ctx, true) }()

	select {
	case <-ui.shows:
	case err := <-done:
		t.Fatalf("first Desktop exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial ShowWindow")
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- Desktop(ctx, true) }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second Desktop returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Desktop did not exit after forwarding show")
	}

	select {
	case appKey := <-ui.shows:
		if appKey != "" {
			t.Fatalf("forwarded ShowWindow appKey = %q, want empty", appKey)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first Desktop did not receive forwarded ShowWindow")
	}

	if got := uiStarts.Load(); got != 1 {
		t.Fatalf("startDesktopUI calls = %d, want 1", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Desktop returned error on cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first Desktop did not exit on cancel")
	}
}

func TestDesktopQuitStopsWithoutReconnecting(t *testing.T) {
	var quitPosted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/state":
			_ = json.NewEncoder(w).Encode(map[string]any{"routing": "on"})
		case "/api/quit":
			quitPosted.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldDial, oldStartUI, oldInterval := dialIPC, startDesktopUI, desktopStateInterval
	t.Cleanup(func() {
		dialIPC = oldDial
		startDesktopUI = oldStartUI
		desktopStateInterval = oldInterval
	})
	desktopStateInterval = 20 * time.Millisecond

	ui := newFakeDesktopUI()
	cbCh := make(chan desktop.UICallbacks, 1)
	startDesktopUI = func(cb desktop.UICallbacks) desktop.UI {
		select {
		case cbCh <- cb:
		default:
		}
		return ui
	}

	var dialCalls atomic.Int32
	var connsMu sync.Mutex
	var openServers []io.Closer
	dialIPC = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		dialCalls.Add(1)
		client, server := net.Pipe()
		connsMu.Lock()
		openServers = append(openServers, server)
		connsMu.Unlock()
		go serveMockDesktopIPC(t, server, func(int) map[string]any {
			return map[string]any{"token": "tok-quit", "url": srv.URL, "ownerName": "Owner"}
		})
		return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: CurrentUser()}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Desktop(ctx, false) }()

	var cb desktop.UICallbacks
	select {
	case cb = <-cbCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for desktop.UICallbacks")
	}

	// Wait until session polling is live before triggering Quit.
	select {
	case st := <-ui.states:
		if !st.reachable {
			t.Fatalf("expected reachable initial state, got %+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial state")
	}

	dialsBeforeQuit := dialCalls.Load()
	cb.Quit()

	select {
	case <-ui.quitting:
	case <-time.After(2 * time.Second):
		t.Fatal("SetQuitting was not called")
	}

	// Simulate Control closing the IPC pipe while/after /api/quit runs.
	connsMu.Lock()
	for _, s := range openServers {
		_ = s.Close()
	}
	connsMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Desktop returned error on quit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Desktop did not exit after Quit")
	}

	if !quitPosted.Load() {
		t.Fatal("/api/quit was not posted")
	}
	if !ui.closed.Load() {
		t.Fatal("UI was not closed on exit")
	}
	if got := dialCalls.Load(); got != dialsBeforeQuit {
		t.Fatalf("dialIPC called after Quit (%d -> %d); expected no reconnect", dialsBeforeQuit, got)
	}
}

func TestDesktopPollsStateAndRefreshes401Token(t *testing.T) {
	var expiredOnce atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/state" {
			http.NotFound(w, r)
			return
		}
		switch r.Header.Get("X-Token") {
		case "tok-initial":
			expiredOnce.Store(true)
			w.WriteHeader(http.StatusUnauthorized)
		case "tok-refreshed":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"routing": "on",
				"tag":     "after-refresh",
			})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	oldDial, oldStartUI, oldInterval := dialIPC, startDesktopUI, desktopStateInterval
	t.Cleanup(func() {
		dialIPC = oldDial
		startDesktopUI = oldStartUI
		desktopStateInterval = oldInterval
	})
	desktopStateInterval = 15 * time.Millisecond

	ui := newFakeDesktopUI()
	startDesktopUI = func(cb desktop.UICallbacks) desktop.UI { return ui }

	var sessionCalls atomic.Int32
	dialIPC = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		client, server := net.Pipe()
		go serveMockDesktopIPC(t, server, func(int) map[string]any {
			n := sessionCalls.Add(1)
			tok := "tok-initial"
			if n >= 2 {
				tok = "tok-refreshed"
			}
			return map[string]any{"token": tok, "url": srv.URL, "ownerName": "Owner"}
		})
		return &localipc.Conn{ReadWriteCloser: client, Peer: localipc.Peer{User: CurrentUser()}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Desktop(ctx, false) }()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case st := <-ui.states:
			if st.reachable && st.raw != nil && st.raw["tag"] == "after-refresh" {
				if !expiredOnce.Load() {
					t.Fatal("reached refreshed state without observing initial 401")
				}
				ui.mu.Lock()
				gotTok := ui.sessionToken
				ui.mu.Unlock()
				if gotTok != "tok-refreshed" {
					t.Fatalf("UI session token = %q, want tok-refreshed", gotTok)
				}
				cancel()
				if err := <-done; err != nil {
					t.Fatalf("Desktop exit error: %v", err)
				}
				return
			}
		case err := <-done:
			t.Fatalf("Desktop exited unexpectedly: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for refreshed state after 401")
		}
	}
}
