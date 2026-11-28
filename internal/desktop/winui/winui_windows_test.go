//go:build windows

package winui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/kekawia/net-switch/internal/desktop"
)

func TestNotifyIconDataSize64(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if got := unsafe.Sizeof(notifyIconDataW{}); got != 976 {
			t.Fatalf("notifyIconDataW size = %d, want 976 on 64-bit Windows", got)
		}
	}
}

func TestIconHIconCreation(t *testing.T) {
	views := []desktop.TrayView{
		desktop.WaitingTray(),
		desktop.TrayFromState(sampleFlyoutState("")),
		desktop.UnreachableTray(false),
	}
	for _, size := range []int{16, 20, 24, 32} {
		for _, v := range views {
			h, err := CreateHIcon(v, size)
			if err != nil {
				t.Fatalf("CreateHIcon(%d): %v", size, err)
			}
			if h == 0 {
				t.Fatalf("CreateHIcon(%d) returned 0", size)
			}
			DestroyHIcon(h)
		}
	}
}

func TestFlyoutSnapshotsMultiDPI(t *testing.T) {
	healthy := desktop.FlyoutFromState(sampleFlyoutState(""))
	resetErr := desktop.FlyoutFromState(sampleFlyoutState("Corrupt usage history preserved as usage.json.corrupt-1; accounting continues: unexpected EOF"))
	saveErr := desktop.FlyoutFromState(sampleFlyoutState("Usage history unavailable; routing continues: permission denied"))
	vpnProxy := desktop.FlyoutFromState(sampleVPNProxyFlyoutState())
	unavail := desktop.UnavailableFlyout("Net Switch isn\u2019t responding.")
	outDir := os.Getenv("NETSWITCH_FLYOUT_SNAPSHOT_DIR")

	for _, scale := range []float64{1.0, 1.5, 2.0} {
		for name, view := range map[string]desktop.FlyoutView{
			"healthy":     healthy,
			"resetErr":    resetErr,
			"saveErr":     saveErr,
			"vpnProxy":    vpnProxy,
			"unavailable": unavail,
		} {
			raw, err := SnapshotPNG(view, scale)
			if err != nil {
				t.Fatalf("SnapshotPNG(%s, %.1f): %v", name, scale, err)
			}
			img, err := png.Decode(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("decode PNG(%s, %.1f): %v", name, scale, err)
			}
			wantW := int(math.Round(float64(flyoutWidthDip) * scale))
			if img.Bounds().Dx() != wantW {
				t.Fatalf("%s@%.1fx width = %d, want %d", name, scale, img.Bounds().Dx(), wantW)
			}
			if img.Bounds().Dy() < int(math.Round(180*scale)) {
				t.Fatalf("%s@%.1fx height %d unexpectedly small", name, scale, img.Bounds().Dy())
			}
			if outDir != "" {
				p := filepath.Join(outDir, fmt.Sprintf("flyout-%s-%.1fx.png", name, scale))
				if err := os.WriteFile(p, raw, 0o600); err != nil {
					t.Fatalf("write snapshot %s: %v", p, err)
				}
			}
		}
	}

	if resetErr.Tone != "ok" || resetErr.HealthTone != "info" || resetErr.Health != "Saved data use was reset" {
		t.Fatalf("unexpected reset usageError flyout model: %+v", resetErr)
	}
	if saveErr.Tone != "ok" || saveErr.HealthTone != "info" || saveErr.Health != "Can\u2019t save data use right now" {
		t.Fatalf("unexpected unavailable usageError flyout model: %+v", saveErr)
	}
}

func TestTrayAndFlyoutLoopTaskbarCreated(t *testing.T) {
	loop, err := StartLoop("Net Switch test tray")
	if err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	defer loop.Close()

	var clicked atomic.Int32
	tray, err := NewTrayIcon(loop, TrayCallbacks{
		OnToggleFlyout: func(_, _ int32) { clicked.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewTrayIcon: %v", err)
	}
	defer tray.Close()

	flyout, err := NewFlyoutWindow(loop, func(FlyoutAction) {})
	if err != nil {
		t.Fatalf("NewFlyoutWindow: %v", err)
	}
	defer flyout.Close()

	flyout.SetView(desktop.FlyoutFromState(sampleFlyoutState("")))
	if err := tray.Update(desktop.TrayFromState(sampleFlyoutState(""))); err != nil {
		t.Fatalf("tray.Update: %v", err)
	}

	// Simulate Explorer broadcasting TaskbarCreated and verify safe recovery on UI thread.
	err = loop.Do(func() error {
		if loop.taskbarCreated != 0 {
			_, _ = loop.handleMessage(loop.trayHwnd, loop.taskbarCreated, 0, 0)
		}
		// Synthetic tray left click invokes callback.
		_, _ = loop.handleMessage(loop.trayHwnd, wmTrayCallback, 0, ninSelect)
		return nil
	})
	if err != nil {
		t.Fatalf("loop.Do: %v", err)
	}
	if clicked.Load() != 1 {
		t.Fatalf("tray click count = %d, want 1", clicked.Load())
	}
}

// One left click on a version 4 icon arrives as Windows 11 delivered it on
// 2026-11-28: button down, button up, then NIN_SELECT. The flyout must toggle
// once; toggling on both opened it and closed it again 4 ms later.
func TestTrayClickTogglesTheFlyoutOnce(t *testing.T) {
	loop, err := StartLoop("Net Switch test tray click")
	if err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	defer loop.Close()

	var toggles atomic.Int32
	tray, err := NewTrayIcon(loop, TrayCallbacks{
		OnToggleFlyout: func(_, _ int32) { toggles.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewTrayIcon: %v", err)
	}
	defer tray.Close()

	send := func(version4 bool, events ...uintptr) int32 {
		t.Helper()
		toggles.Store(0)
		if err := loop.Do(func() error {
			tray.version4 = version4
			for _, ev := range events {
				_, _ = loop.handleMessage(loop.trayHwnd, wmTrayCallback, 0, ev)
			}
			return nil
		}); err != nil {
			t.Fatalf("loop.Do: %v", err)
		}
		return toggles.Load()
	}
	for _, c := range []struct {
		name     string
		version4 bool
		events   []uintptr
	}{
		{"mouse click, version 4", true, []uintptr{wmLButtonDown, wmLButtonUp, ninSelect}},
		{"Enter or Space on the icon, version 4", true, []uintptr{ninKeySelect}},
		{"mouse click without version 4", false, []uintptr{wmLButtonDown, wmLButtonUp}},
	} {
		if got := send(c.version4, c.events...); got != 1 {
			t.Errorf("%s: flyout toggled %d times, want once", c.name, got)
		}
	}
}

func TestWebView2EndToEndAndFallback(t *testing.T) {
	// 1. Disabled/fallback path via environment override.
	t.Run("FallbackWhenDisabled", func(t *testing.T) {
		t.Setenv("NETSWITCH_DISABLE_WEBVIEW2", "1")
		loop, err := StartLoop("Net Switch fallback test")
		if err != nil {
			t.Fatalf("StartLoop: %v", err)
		}
		defer loop.Close()

		got := make(chan string, 1)
		win := NewWebView2Window(loop, WebView2Callbacks{
			URL:           func() string { return "http://127.0.0.1:1/" },
			OffscreenTest: true,
			OnFallback: func(reason string) {
				got <- reason
			},
		})
		defer win.Close()
		if err := win.Open(""); err != nil {
			t.Fatalf("Open: %v", err)
		}
		select {
		case r := <-got:
			if r == "" {
				t.Fatal("expected non-empty fallback reason")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for WebView2 fallback")
		}
	})

	// 2. Real offscreen WebView2 host test using staged WebView2Loader.dll.
	if os.Getenv("NETSWITCH_WEBVIEW2_LOADER_DIR") == "" {
		t.Skip("NETSWITCH_WEBVIEW2_LOADER_DIR is not set")
	}

	var mu sync.Mutex
	token := "tok-initial-1"
	var forceOne401 atomic.Bool
	forceOne401.Store(true)
	apiSeenToken := make(chan string, 8)
	blockedExternal := make(chan string, 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body><script>
const wv = window.chrome && window.chrome.webview;
let tok = "";
async function pollState() {
  const res = await fetch('/api/state', { headers: { 'X-Token': tok }, credentials: 'omit' });
  if (res.status === 401 && wv) {
    wv.postMessage(JSON.stringify({ type: 'netswitch-refresh-token' }));
  }
}
if (wv) {
  wv.addEventListener('message', async (ev) => {
    let msg = ev.data;
    if (typeof msg === 'string') msg = JSON.parse(msg);
    if (msg && msg.type === 'netswitch-session' && msg.token) {
      tok = msg.token;
      await pollState();
      if (!window.__navTried) {
        window.__navTried = true;
        setTimeout(() => { window.open('https://example.com/blocked-popup', '_blank'); }, 50);
      }
    } else if (msg && msg.type === 'netswitch-token' && msg.token) {
      tok = msg.token;
      await pollState();
    }
  });
  wv.postMessage(JSON.stringify({ type: 'netswitch-ready' }));
}
</script></body></html>`))
		case "/api/state":
			gotTok := r.Header.Get("X-Token")
			mu.Lock()
			cur := token
			mu.Unlock()
			if forceOne401.CompareAndSwap(true, false) || gotTok != cur {
				apiSeenToken <- "401:" + gotTok
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			apiSeenToken <- "200:" + gotTok
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	loop, err := StartLoop("Net Switch WebView2 test")
	if err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	defer loop.Close()

	var refreshCount atomic.Int32
	fallbackCh := make(chan string, 2)
	win := NewWebView2Window(loop, WebView2Callbacks{
		URL: func() string { return srv.URL + "/" },
		Token: func() string {
			mu.Lock()
			defer mu.Unlock()
			return token
		},
		OnRefreshToken: func(context.Context) (string, bool) {
			refreshCount.Add(1)
			mu.Lock()
			token = "tok-refreshed-2"
			cur := token
			mu.Unlock()
			return cur, true
		},
		OpenExternal: func(uri string) error {
			blockedExternal <- uri
			return nil
		},
		OnFallback: func(reason string) {
			fallbackCh <- reason
		},
		UserDataDir:   t.TempDir(),
		OffscreenTest: true,
	})
	defer win.Close()

	if err := win.Open(""); err != nil {
		t.Fatalf("win.Open: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	got401 := false
	gotRefreshed := false
	for !got401 || !gotRefreshed {
		select {
		case evt := <-apiSeenToken:
			if evt == "401:tok-initial-1" {
				got401 = true
			}
			if evt == "200:tok-refreshed-2" {
				gotRefreshed = true
			}
		case reason := <-fallbackCh:
			if strings.Contains(strings.ToLower(reason), "not installed") || strings.Contains(strings.ToLower(reason), "unavailable") {
				t.Skipf("Edge WebView2 runtime unavailable on this machine: %s", reason)
			}
			t.Fatalf("unexpected WebView2 fallback: %s", reason)
		case <-time.After(time.Until(deadline)):
			t.Fatalf("timed out waiting for WebView2 401->refresh->200 sequence (got401=%v gotRefreshed=%v)", got401, gotRefreshed)
		}
	}
	if refreshCount.Load() != 1 {
		t.Fatalf("refreshCount = %d, want 1", refreshCount.Load())
	}

	// Verify put_Bounds -> get_Bounds round-trip on active architecture (amd64 / arm64).
	bounds, err := win.Bounds()
	if err != nil {
		t.Fatalf("Bounds: %v", err)
	}
	if bounds.Right-bounds.Left <= 0 || bounds.Bottom-bounds.Top <= 0 {
		t.Fatalf("unexpected WebView2 controller bounds: %+v", bounds)
	}
	// Controller.Close is asynchronous with respect to the browser process
	// group. Keep the environment alive until its exit event releases the UDF.
	exitWatch := watchWebViewBrowserExit(t, win)
	defer exitWatch.close(t)
	exitWatch.waitForController(t)

	// Verify external https:// popup/link intercepted cleanly by OpenExternal without navigating inside WebView2.
	select {
	case ext := <-blockedExternal:
		if ext != "https://example.com/blocked-popup" {
			t.Fatalf("unexpected external URI: %q", ext)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for NewWindowRequested interception")
	}

	// Verify ProcessFailed recreates 3 times, then falls back on 4th crash within 5 min.
	for i := 0; i < 3; i++ {
		win.TriggerTestCrash()
		// Each injected failure must finish recreating its controller before
		// the next failure, so there is no unobserved pending creation at close.
		exitWatch.waitForController(t)
	}
	select {
	case r := <-fallbackCh:
		t.Fatalf("fallback triggered early after 3 crashes: %s", r)
	default:
	}
	win.TriggerTestCrash()
	select {
	case r := <-fallbackCh:
		if !strings.Contains(r, "3 times") {
			t.Fatalf("unexpected 4th-crash fallback reason: %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected fallback after 4th WebView2 crash")
	}
}

// These IIDs and vtable slots are from the pinned WebView2 1.0.4314.35 header.
// BrowserProcessExited covers the entire browser process group, including
// children which can still write the profile after the controller is closed.
// https://learn.microsoft.com/microsoft-edge/webview2/concepts/process-related-events
type webViewBrowserExitWatch struct {
	window *WebView2Window
	env    uintptr
	token  int64
	pid    uint32
	exited chan uint32
}

func watchWebViewBrowserExit(t *testing.T, window *WebView2Window) *webViewBrowserExitWatch {
	t.Helper()
	w := &webViewBrowserExitWatch{window: window, exited: make(chan uint32, 8)}
	err := window.loop.Do(func() error {
		w.env = comQueryInterface(window.env, mustGUID("{319e423d-e0d7-4b8d-9254-ae9475de9b17}"))
		if w.env == 0 {
			return fmt.Errorf("ICoreWebView2Environment5 is unavailable")
		}
		handler := newCOMCallback(mustGUID("{fa504257-a216-4911-a860-fe8825712861}"), func(_, args uintptr) {
			var pid uint32
			if hr := comCall1(args, 4, uintptr(unsafe.Pointer(&pid))); int32(hr) >= 0 {
				select {
				case w.exited <- pid:
				default:
				}
			}
		})
		defer comRelease(handler)
		if hr := comCall2(w.env, 12, handler, uintptr(unsafe.Pointer(&w.token))); int32(hr) < 0 {
			comRelease(w.env)
			w.env = 0
			return fmt.Errorf("add_BrowserProcessExited: 0x%08x", uint32(hr))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *webViewBrowserExitWatch) waitForController(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := false
		err := w.window.loop.Do(func() error {
			if w.window.initializing || w.window.webview == 0 {
				return nil
			}
			if hr := comCall1(w.window.webview, 37, uintptr(unsafe.Pointer(&w.pid))); int32(hr) < 0 || w.pid == 0 {
				return fmt.Errorf("get_BrowserProcessId: 0x%08x pid=%d", uint32(hr), w.pid)
			}
			ready = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("WebView2 controller recreation did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (w *webViewBrowserExitWatch) close(t *testing.T) {
	t.Helper()
	defer func() {
		if err := w.window.loop.Do(func() error {
			hr := comCall1(w.env, 13, uintptr(w.token))
			comRelease(w.env)
			if int32(hr) < 0 {
				return fmt.Errorf("remove_BrowserProcessExited: 0x%08x", uint32(hr))
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	}()
	w.window.Close()
	if w.pid == 0 {
		return // The test failed before observing a recreated controller.
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case pid := <-w.exited:
			if pid == w.pid {
				t.Logf("WEBVIEW2_PROFILE_RELEASED browser_pid=%d browser_process_group_exited=true", pid)
				return
			}
		case <-deadline.C:
			t.Errorf("WebView2 browser process group %d did not exit before profile cleanup", w.pid)
			return
		}
	}
}

func sampleFlyoutState(usageErr string) map[string]any {
	state := map[string]any{
		"routing": map[string]any{"status": "on", "wanted": true},
		"combine": map[string]any{"on": true, "active": true},
		"lines": []any{
			map[string]any{
				"id":        "cable",
				"label":     "Cable",
				"alias":     "Ethernet",
				"connected": true,
				"ping":      14.0,
				"rate":      map[string]any{"down": 420.0 * 1024, "up": 85.0 * 1024},
			},
			map[string]any{
				"id":        "wifi",
				"label":     "Wi-Fi stick",
				"alias":     "Wi-Fi",
				"ssid":      "Studio-5G",
				"connected": true,
				"metered":   true,
				"ping":      28.0,
				"usage":     map[string]any{"bytes": 1.4 * 1024 * 1024 * 1024},
				"cap":       map[string]any{"bytes": 5.0 * 1024 * 1024 * 1024, "period": "month"},
				"rate":      map[string]any{"down": 2.3 * 1024 * 1024, "up": 410.0 * 1024},
			},
		},
		"apps": []any{
			map[string]any{
				"name":      "Discord",
				"path":      `C:\Users\User\AppData\Local\Discord\Discord.exe`,
				"line":      "cable",
				"sortScore": 300.0,
				"rate":      map[string]any{"down": 180.0 * 1024, "up": 32.0 * 1024},
			},
			map[string]any{
				"name":      "Google Chrome",
				"path":      `C:\Program Files\Google\Chrome\Application\chrome.exe`,
				"sortScore": 200.0,
				"rate":      map[string]any{"down": 1.8 * 1024 * 1024, "up": 120.0 * 1024},
			},
		},
	}
	if usageErr != "" {
		state["usageError"] = usageErr
	}
	return state
}

func sampleVPNProxyFlyoutState() map[string]any {
	return map[string]any{
		"routing": map[string]any{"status": "on", "wanted": true},
		"combine": map[string]any{"on": true, "active": true},
		"lines": []any{
			map[string]any{
				"id": "cable", "label": "Cable", "alias": "Ethernet", "main": true,
				"connected": true, "ping": 18.0,
				"rate": map[string]any{"down": 840.0 * 1024, "up": 30.0 * 1024},
			},
			map[string]any{
				"id": "wifi", "label": "Wi-Fi stick", "alias": "Wi-Fi", "main": false,
				"connected": true, "metered": true, "ping": 24.0,
				"usage": map[string]any{"bytes": 1.2 * 1024 * 1024 * 1024},
				"cap":   map[string]any{"bytes": 10.0 * 1024 * 1024 * 1024, "period": "month"},
				"rate":  map[string]any{"down": 120.0 * 1024, "up": 12.0 * 1024},
			},
			map[string]any{
				"id": "vpn1", "label": "Proton VPN", "alias": "ProtonVPN", "main": false,
				"vpn": true, "onlyChosen": true, "connected": true, "ping": 31.0,
				"rate": map[string]any{"down": 410.0 * 1024, "up": 18.0 * 1024},
			},
			map[string]any{
				"id": "px1", "label": "NL proxy", "alias": "proxy:px1", "main": false,
				"onlyChosen": true, "connected": true, "ping": 19.0,
				"proxy": map[string]any{"protocol": "socks5", "server": "127.0.0.1:1080", "carrier": "local", "udp": true},
				"rate":  map[string]any{"down": 95.0 * 1024, "up": 8.0 * 1024},
			},
		},
		"apps": []any{
			map[string]any{
				"name": "Claude", "path": `C:\Users\User\AppData\Local\Claude\Claude.exe`,
				"sortScore": 612.0, "rate": map[string]any{"down": 612.0 * 1024, "up": 24.0 * 1024},
			},
			map[string]any{
				"name": "qBittorrent", "path": `C:\Program Files\qBittorrent\qbittorrent.exe`,
				"line": "vpn1", "sortScore": 410.0, "rate": map[string]any{"down": 410.0 * 1024, "up": 18.0 * 1024},
			},
			map[string]any{
				"name": "Floorp", "path": `C:\Program Files\Floorp\floorp.exe`,
				"line": "px1", "sortScore": 95.0, "rate": map[string]any{"down": 95.0 * 1024, "up": 8.0 * 1024},
			},
		},
	}
}
