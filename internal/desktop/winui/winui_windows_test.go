//go:build windows

package winui

import (
	"bytes"
	"context"
	"encoding/json"
	"image/png"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/desktop"
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
	unavail := desktop.UnavailableFlyout("Net Switch isn\u2019t responding.")

	for _, scale := range []float64{1.0, 1.5, 2.0} {
		for name, view := range map[string]desktop.FlyoutView{
			"healthy":     healthy,
			"resetErr":    resetErr,
			"saveErr":     saveErr,
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
	}
	select {
	case r := <-fallbackCh:
		t.Fatalf("fallback triggered early after 3 crashes: %s", r)
	case <-time.After(300 * time.Millisecond):
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
