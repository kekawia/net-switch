//go:build windows

package winui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/AyoubAchour/net-switch/internal/desktop"
)

const (
	gmemFixedZeroInit = 0x0040
	wmSetIcon         = 0x0080
	iconSmall         = 0
	iconBig           = 1
	swHideWindow      = 0
	swShowWindow      = 5
	swShowNoActivate  = 8
	swRestoreWindow   = 9
	gwlpUserData      = ^uintptr(20) // -21
	wsOverlappedWinEx = 0x00CF0000 | wsClipChildren

	webviewMinWidth  = 780
	webviewMinHeight = 520
	webviewDefWidth  = 980
	webviewDefHeight = 720
)

// Pinned SHA-256 hashes from packaging/versions.json (Microsoft.Web.WebView2 1.0.4314.35).
var pinnedWebView2Loader = map[string]string{
	"amd64": "d3fce90bdeecb08596e377dea6a316354dd8949e32ff09b89d51be00c14e21b6",
	"arm64": "05429881d918fd64a3fe4955155c1af79e66d7b7d944034467874f420bc2265a",
}

var (
	iidIUnknown         = mustGUID("{00000000-0000-0000-C000-000000000046}")
	iidEnvCompleted     = mustGUID("{4e8a3389-c9d8-4bd2-b6b5-124fee6cc14d}")
	iidCtrlCompleted    = mustGUID("{6c4819f3-c9b7-4260-8127-c9f5bde7f68c}")
	iidController2      = mustGUID("{c979903e-d4ca-4228-92eb-47ee3fa96eab}")
	iidSettings3        = mustGUID("{fdb5ab74-af33-4854-84f0-0a631deb5eba}")
	iidSettings4        = mustGUID("{cb56846c-4168-4d53-b04f-03b6d6796ff2}")
	iidSettings6        = mustGUID("{11cb3acd-9bc8-43b8-83bf-f40753714f87}")
	iidNavStarting      = mustGUID("{9adbe429-f36d-432b-9ddc-f8881fbd76e3}")
	iidNewWindowReq     = mustGUID("{d4c185fe-c81c-4989-97af-2d3fa7ab5651}")
	iidWebMsgReceived   = mustGUID("{57213f19-00e6-49fa-8e07-898ea01ecbd2}")
	iidProcessFailed    = mustGUID("{79e0aea4-990b-42d9-aa1d-0fcc2e5bc7f1}")
	hresultNoInterface  = ^uintptr(0x7FFFBFFD) // E_NOINTERFACE (0x80004002)
	hresultInvalidArg   = ^uintptr(0x7FF8FFA8) // E_INVALIDARG (0x80070057)
	procAdjustWindowEx  = user32.NewProc("AdjustWindowRectExForDpi")
	procGetDpiForWindow = user32.NewProc("GetDpiForWindow")
)

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

type minMaxInfo struct {
	ptReserved     winPoint
	ptMaxSize      winPoint
	ptMaxPosition  winPoint
	ptMinTrackSize winPoint
	ptMaxTrackSize winPoint
}

// WebView2Callbacks supplies URLs, tokens, and lifecycle hooks to the window.
type WebView2Callbacks struct {
	URL            func() string
	Token          func() string
	OnRefreshToken func(context.Context) (string, bool)
	OnQuit         func()
	OnFallback     func(reason string)
	OpenExternal   func(uri string) error
	UserDataDir    string
	OffscreenTest  bool
}

// WebView2Window hosts Net Switch's local web app inside a hardened Edge
// WebView2 window with pure-Go COM bindings and automatic /pair browser fallback.
type WebView2Window struct {
	loop          *Loop
	cb            WebView2Callbacks
	hwnd          uintptr
	env           uintptr
	ctrl          uintptr
	webview       uintptr
	userDataDir   string
	loadedOrigin  string
	loadedURL     string
	visible       bool
	initializing  bool
	fallbackSent  bool
	closed        bool
	crashTimes    []time.Time
	pendingFocus  string
	loaderMu      sync.Mutex
	loaderModule  windows.Handle
	loaderFile    *os.File
	createEnvProc uintptr
	getVerProc    uintptr
	hIconBig      uintptr
	hIconSmall    uintptr
}

// NewWebView2Window constructs the window controller bound to loop.
func NewWebView2Window(loop *Loop, cb WebView2Callbacks) *WebView2Window {
	return &WebView2Window{
		loop: loop,
		cb:   cb,
	}
}

// Open shows the main Net Switch window (creating WebView2 if needed, or
// invoking OnFallback when WebView2 runtime/loader is unavailable).
func (w *WebView2Window) Open(focusApp string) error {
	if w == nil || w.loop == nil {
		return errors.New("webview2 window requires an active Loop")
	}
	return w.loop.Do(func() error {
		if w.closed {
			return nil
		}
		w.visible = true
		if focusApp != "" {
			w.pendingFocus = focusApp
		}
		if w.fallbackSent {
			if w.cb.OnFallback != nil {
				w.cb.OnFallback("webview2 fallback active")
			}
			return nil
		}
		if err := w.ensureHostWindow(); err != nil {
			w.triggerFallback(err.Error())
			return nil
		}
		w.showHostWindow()
		if w.webview != 0 {
			w.syncEndpoint()
			w.sendPendingFocus()
			w.setControllerVisible(true)
			w.updateBounds()
			return nil
		}
		if !w.initializing {
			w.startWebView2()
		}
		return nil
	})
}

// Hide hides the window while keeping routing and tray alive.
func (w *WebView2Window) Hide() {
	if w == nil || w.loop == nil {
		return
	}
	w.loop.Post(func() {
		if w.closed || w.hwnd == 0 {
			return
		}
		w.visible = false
		w.setControllerVisible(false)
		_, _, _ = procShowWindow.Call(w.hwnd, swHideWindow)
	})
}

// NotifyEndpointUpdated updates the running WebView2 session token or reloads
// if Control moved to a different local port.
func (w *WebView2Window) NotifyEndpointUpdated() {
	if w == nil || w.loop == nil {
		return
	}
	w.loop.Post(func() {
		if w.closed || w.webview == 0 {
			return
		}
		w.syncEndpoint()
	})
}

// Bounds returns the current ICoreWebView2Controller bounds rectangle (used in
// tests to verify x64 and ARM64 put_Bounds ABI).
func (w *WebView2Window) Bounds() (winRect, error) {
	if w == nil || w.loop == nil {
		return winRect{}, errors.New("window closed")
	}
	var out winRect
	err := w.loop.Do(func() error {
		if w.ctrl == 0 {
			return errors.New("controller not created")
		}
		var err error
		out, err = getControllerBounds(w.ctrl)
		return err
	})
	return out, err
}

// TriggerTestCrash is used by tests to exercise ProcessFailed recovery logic.
func (w *WebView2Window) TriggerTestCrash() {
	if w == nil || w.loop == nil {
		return
	}
	_ = w.loop.Do(func() error {
		w.handleProcessFailed()
		return nil
	})
}

// Close releases the WebView2 COM interfaces, HWND, and loader lock handle.
func (w *WebView2Window) Close() {
	if w == nil || w.loop == nil {
		return
	}
	_ = w.loop.Do(func() error {
		if w.closed {
			return nil
		}
		w.closed = true
		w.closeController()
		if w.env != 0 {
			comRelease(w.env)
			w.env = 0
		}
		if w.hwnd != 0 {
			w.loop.webProc = nil
			w.loop.webHwnd = 0
			w.loop.unregisterHwnd(w.hwnd)
			_, _, _ = procDestroyWindow.Call(w.hwnd)
			w.hwnd = 0
		}
		DestroyHIcon(w.hIconSmall)
		DestroyHIcon(w.hIconBig)
		w.hIconSmall, w.hIconBig = 0, 0
		return nil
	})
	w.loaderMu.Lock()
	if w.loaderFile != nil {
		_ = w.loaderFile.Close()
		w.loaderFile = nil
	}
	w.loaderMu.Unlock()
}

func (w *WebView2Window) ensureHostWindow() error {
	if w.hwnd != 0 {
		return nil
	}
	w.loop.webProc = w.handleMessage
	cname, err := windows.UTF16PtrFromString("NetSwitchWebViewWindow")
	if err != nil {
		return err
	}
	tname, err := windows.UTF16PtrFromString("Net Switch")
	if err != nil {
		return err
	}
	x, y := uintptr(0x80000000), uintptr(0x80000000) // CW_USEDEFAULT
	if w.cb.OffscreenTest {
		offscreen := -32000
		x = uintptr(offscreen)
		y = uintptr(offscreen)
	}
	hwnd, _, callErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(cname)),
		uintptr(unsafe.Pointer(tname)),
		wsOverlappedWinEx,
		x, y, webviewDefWidth, webviewDefHeight,
		0, 0, w.loop.hInstance, 0,
	)
	runtime.KeepAlive(cname)
	runtime.KeepAlive(tname)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW webview: %w", callErr)
	}
	w.hwnd = hwnd
	w.loop.webHwnd = hwnd
	w.loop.registerHwnd(hwnd)
	darkWindowFrame(hwnd)
	if hSm, err := createWindowDefaultIcon(16); err == nil {
		w.hIconSmall = hSm
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, hSm)
	}
	if hBg, err := createWindowDefaultIcon(32); err == nil {
		w.hIconBig = hBg
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconBig, hBg)
	}
	return nil
}

func (w *WebView2Window) showHostWindow() {
	if w.hwnd == 0 {
		return
	}
	if w.cb.OffscreenTest {
		_, _, _ = procShowWindow.Call(w.hwnd, swShowNoActivate)
		return
	}
	if iconic, _, _ := procIsIconic.Call(w.hwnd); iconic != 0 {
		_, _, _ = procShowWindow.Call(w.hwnd, swRestoreWindow)
	} else {
		_, _, _ = procShowWindow.Call(w.hwnd, swShowWindow)
	}
	_, _, _ = procSetForegroundWindow.Call(w.hwnd)
}

func (w *WebView2Window) handleMessage(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr) {
	switch msg {
	case wmClose:
		w.visible = false
		w.setControllerVisible(false)
		_, _, _ = procShowWindow.Call(hwnd, swHideWindow)
		return true, 0
	case wmSize:
		w.updateBounds()
		if w.ctrl != 0 {
			comCall0(w.ctrl, 23) // NotifyParentWindowPositionChanged
		}
		return true, 0
	case wmGetMinMaxInfo:
		if lParam != 0 {
			scale := 1.0
			if procGetDpiForWindow.Find() == nil {
				if dpi, _, _ := procGetDpiForWindow.Call(hwnd); dpi > 0 {
					scale = float64(dpi) / 96.0
				}
			}
			mmi := (*minMaxInfo)(ptrFromAddr(lParam))
			mmi.ptMinTrackSize.X = int32(float64(webviewMinWidth) * scale)
			mmi.ptMinTrackSize.Y = int32(float64(webviewMinHeight) * scale)
		}
		return true, 0
	}
	return false, 0
}

func (w *WebView2Window) startWebView2() {
	if os.Getenv("NETSWITCH_DISABLE_WEBVIEW2") == "1" {
		w.triggerFallback("WebView2 disabled by environment override")
		return
	}
	if err := w.ensureLoader(); err != nil {
		w.triggerFallback(err.Error())
		return
	}
	if ver, err := w.availableBrowserVersion(); err != nil || ver == "" {
		if err != nil {
			w.triggerFallback("Edge WebView2 runtime check failed: " + err.Error())
		} else {
			w.triggerFallback("Edge WebView2 runtime not installed")
		}
		return
	}
	dataDir := w.cb.UserDataDir
	if dataDir == "" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp == "" {
			localApp, _ = os.UserCacheDir()
		}
		if localApp == "" {
			w.triggerFallback("LOCALAPPDATA is unavailable for WebView2")
			return
		}
		dataDir = filepath.Join(localApp, "Net Switch", "WebView2")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		w.triggerFallback(fmt.Sprintf("create WebView2 data directory: %v", err))
		return
	}
	w.userDataDir = dataDir
	w.initializing = true

	dirPtr, err := windows.UTF16PtrFromString(dataDir)
	if err != nil {
		w.initializing = false
		w.triggerFallback(err.Error())
		return
	}
	handler := newCOMCallback(iidEnvCompleted, func(hr uintptr, env uintptr) {
		comAddRefIfNonZero(env)
		w.loop.Post(func() {
			defer comReleaseIfNonZero(env)
			w.onEnvironmentCreated(hr, env)
		})
	})
	hr, _, _ := syscall.SyscallN(w.createEnvProc, 0, uintptr(unsafe.Pointer(dirPtr)), 0, handler)
	runtime.KeepAlive(dirPtr)
	comRelease(handler)
	if int32(hr) < 0 {
		w.initializing = false
		w.triggerFallback(fmt.Sprintf("CreateCoreWebView2EnvironmentWithOptions: 0x%08x", uint32(hr)))
	}
}

func (w *WebView2Window) onEnvironmentCreated(hr, env uintptr) {
	if w.closed {
		w.initializing = false
		return
	}
	if int32(hr) < 0 || env == 0 {
		w.initializing = false
		w.triggerFallback(fmt.Sprintf("WebView2 environment failed: 0x%08x", uint32(hr)))
		return
	}
	comAddRefIfNonZero(env)
	if w.env != 0 {
		comRelease(w.env)
	}
	w.env = env
	w.createControllerFromEnv()
}

func (w *WebView2Window) createControllerFromEnv() {
	if w.env == 0 || w.hwnd == 0 {
		w.initializing = false
		w.triggerFallback("WebView2 environment missing")
		return
	}
	handler := newCOMCallback(iidCtrlCompleted, func(hr uintptr, ctrl uintptr) {
		comAddRefIfNonZero(ctrl)
		w.loop.Post(func() {
			defer comReleaseIfNonZero(ctrl)
			w.onControllerCreated(hr, ctrl)
		})
	})
	hr := comCall2(w.env, 3, w.hwnd, handler) // CreateCoreWebView2Controller
	comRelease(handler)
	if int32(hr) < 0 {
		w.initializing = false
		w.triggerFallback(fmt.Sprintf("CreateCoreWebView2Controller: 0x%08x", uint32(hr)))
	}
}

func (w *WebView2Window) onControllerCreated(hr, ctrl uintptr) {
	w.initializing = false
	if w.closed {
		return
	}
	if int32(hr) < 0 || ctrl == 0 {
		w.triggerFallback(fmt.Sprintf("WebView2 controller failed: 0x%08x", uint32(hr)))
		return
	}
	w.closeController()
	comAddRefIfNonZero(ctrl)
	w.ctrl = ctrl

	// Dark #0C0E10 default background prevents white flash while page loads.
	if ctrl2 := comQueryInterface(ctrl, iidController2); ctrl2 != 0 {
		darkColor := uintptr(255) | uintptr(12)<<8 | uintptr(14)<<16 | uintptr(16)<<24
		comCall1(ctrl2, 27, darkColor) // put_DefaultBackgroundColor
		comRelease(ctrl2)
	}

	var webview uintptr
	hrGet := comCall1(ctrl, 25, uintptr(unsafe.Pointer(&webview))) // get_CoreWebView2
	if int32(hrGet) < 0 || webview == 0 {
		w.triggerFallback(fmt.Sprintf("get_CoreWebView2: 0x%08x", uint32(hrGet)))
		return
	}
	w.webview = webview

	w.applyHardenedSettings(webview)
	w.attachWebViewHandlers(webview)
	w.updateBounds()
	w.setControllerVisible(w.visible)

	targetURL := ""
	if w.cb.URL != nil {
		targetURL = w.cb.URL()
	}
	if targetURL != "" {
		w.navigateTo(targetURL)
	}
}

func (w *WebView2Window) applyHardenedSettings(wv uintptr) {
	var settings uintptr
	if hr := comCall1(wv, 3, uintptr(unsafe.Pointer(&settings))); int32(hr) < 0 || settings == 0 {
		return
	}
	defer comRelease(settings)
	comCall1(settings, 4, 1)  // put_IsScriptEnabled(TRUE)
	comCall1(settings, 6, 1)  // put_IsWebMessageEnabled(TRUE)
	comCall1(settings, 8, 0)  // put_AreDefaultScriptDialogsEnabled(FALSE)
	comCall1(settings, 10, 0) // put_IsStatusBarEnabled(FALSE)
	comCall1(settings, 12, 0) // put_AreDevToolsEnabled(FALSE)
	comCall1(settings, 14, 0) // put_AreDefaultContextMenusEnabled(FALSE)
	comCall1(settings, 16, 0) // put_AreHostObjectsAllowed(FALSE)
	comCall1(settings, 18, 0) // put_IsZoomControlEnabled(FALSE)
	comCall1(settings, 20, 0) // put_IsBuiltInErrorPageEnabled(FALSE)
	if s3 := comQueryInterface(settings, iidSettings3); s3 != 0 {
		comCall1(s3, 24, 0) // put_AreBrowserAcceleratorKeysEnabled(FALSE)
		comRelease(s3)
	}
	if s4 := comQueryInterface(settings, iidSettings4); s4 != 0 {
		comCall1(s4, 26, 0) // put_IsPasswordAutosaveEnabled(FALSE)
		comCall1(s4, 28, 0) // put_IsGeneralAutofillEnabled(FALSE)
		comRelease(s4)
	}
	if s6 := comQueryInterface(settings, iidSettings6); s6 != 0 {
		comCall1(s6, 32, 0) // put_IsSwipeNavigationEnabled(FALSE)
		comRelease(s6)
	}
}

func (w *WebView2Window) attachWebViewHandlers(wv uintptr) {
	var tok int64
	navCB := newCOMCallback(iidNavStarting, func(_ uintptr, args uintptr) {
		var uriPtr uintptr
		if args != 0 && int32(comCall1(args, 3, uintptr(unsafe.Pointer(&uriPtr)))) >= 0 && uriPtr != 0 {
			uri := takeCoTaskMemString(uriPtr)
			if !w.isAllowedOrigin(uri) {
				comCall1(args, 8, 1) // put_Cancel(TRUE)
				if strings.HasPrefix(uri, "https://") {
					openURL := uri
					go func() { _ = w.openExternal(openURL) }()
				}
			}
		}
	})
	comCall2(wv, 7, navCB, uintptr(unsafe.Pointer(&tok))) // add_NavigationStarting
	comRelease(navCB)

	newWinCB := newCOMCallback(iidNewWindowReq, func(_ uintptr, args uintptr) {
		if args == 0 {
			return
		}
		comCall1(args, 6, 1) // put_Handled(TRUE)
		var uriPtr uintptr
		if int32(comCall1(args, 3, uintptr(unsafe.Pointer(&uriPtr)))) >= 0 && uriPtr != 0 {
			uri := takeCoTaskMemString(uriPtr)
			if strings.HasPrefix(uri, "https://") {
				openURL := uri
				go func() { _ = w.openExternal(openURL) }()
			}
		}
	})
	comCall2(wv, 44, newWinCB, uintptr(unsafe.Pointer(&tok))) // add_NewWindowRequested
	comRelease(newWinCB)

	msgCB := newCOMCallback(iidWebMsgReceived, func(_ uintptr, args uintptr) {
		if args == 0 {
			return
		}
		var srcPtr, msgPtr uintptr
		if int32(comCall1(args, 3, uintptr(unsafe.Pointer(&srcPtr)))) < 0 || srcPtr == 0 {
			return
		}
		src := takeCoTaskMemString(srcPtr)
		if !w.isAllowedOrigin(src) {
			return
		}
		if int32(comCall1(args, 4, uintptr(unsafe.Pointer(&msgPtr)))) < 0 || msgPtr == 0 {
			return
		}
		raw := takeCoTaskMemString(msgPtr)
		w.loop.Post(func() {
			w.handleWebMessage(raw)
		})
	})
	comCall2(wv, 34, msgCB, uintptr(unsafe.Pointer(&tok))) // add_WebMessageReceived
	comRelease(msgCB)

	crashCB := newCOMCallback(iidProcessFailed, func(_ uintptr, _ uintptr) {
		w.loop.Post(func() {
			w.handleProcessFailed()
		})
	})
	comCall2(wv, 25, crashCB, uintptr(unsafe.Pointer(&tok))) // add_ProcessFailed
	comRelease(crashCB)
}

func (w *WebView2Window) handleWebMessage(raw string) {
	msgType := parseWebMessageType(raw)
	switch msgType {
	case "netswitch-ready":
		if w.cb.Token != nil {
			if tok := w.cb.Token(); tok != "" {
				w.postSessionToken(tok)
			}
		}
		w.sendPendingFocus()
	case "netswitch-refresh-token":
		if w.cb.OnRefreshToken == nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if nextTok, ok := w.cb.OnRefreshToken(ctx); ok && nextTok != "" {
				w.loop.Post(func() {
					if !w.closed && w.webview != 0 {
						w.postSessionToken(nextTok)
					}
				})
			}
		}()
	case "netswitch-quit":
		if w.cb.OnQuit != nil {
			go w.cb.OnQuit()
		}
	}
}

func parseWebMessageType(raw string) string {
	var inner string
	if json.Unmarshal([]byte(raw), &inner) == nil && inner != "" {
		raw = inner
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(raw), &obj) == nil {
		return obj.Type
	}
	return ""
}

func (w *WebView2Window) postSessionToken(tok string) {
	if w.webview == 0 || tok == "" {
		return
	}
	b, _ := json.Marshal(map[string]string{
		"type":  "netswitch-session",
		"token": tok,
	})
	w.postJSONMessage(string(b))
}

func (w *WebView2Window) sendPendingFocus() {
	if w.webview == 0 || w.pendingFocus == "" {
		return
	}
	app := w.pendingFocus
	w.pendingFocus = ""
	b, _ := json.Marshal(map[string]string{
		"type": "netswitch-focus-app",
		"path": app,
	})
	w.postJSONMessage(string(b))
}

func (w *WebView2Window) postJSONMessage(payload string) {
	if w.webview == 0 {
		return
	}
	ptr, err := windows.UTF16PtrFromString(payload)
	if err != nil {
		return
	}
	comCall1(w.webview, 32, uintptr(unsafe.Pointer(ptr))) // PostWebMessageAsJson
	runtime.KeepAlive(ptr)
}

func (w *WebView2Window) syncEndpoint() {
	if w.webview == 0 {
		return
	}
	target := ""
	if w.cb.URL != nil {
		target = w.cb.URL()
	}
	origin := originOf(target)
	if target != "" && origin != "" && origin != w.loadedOrigin {
		w.navigateTo(target)
		return
	}
	if w.cb.Token != nil {
		if tok := w.cb.Token(); tok != "" {
			w.postSessionToken(tok)
		}
	}
}

func (w *WebView2Window) navigateTo(target string) {
	if w.webview == 0 || target == "" {
		return
	}
	w.loadedURL = target
	w.loadedOrigin = originOf(target)
	ptr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return
	}
	comCall1(w.webview, 5, uintptr(unsafe.Pointer(ptr))) // Navigate
	runtime.KeepAlive(ptr)
}

func (w *WebView2Window) handleProcessFailed() {
	if w.closed || w.fallbackSent {
		return
	}
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)
	kept := w.crashTimes[:0]
	for _, ts := range w.crashTimes {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	w.crashTimes = append(kept, now)
	if len(w.crashTimes) > 3 {
		w.closeController()
		if w.hwnd != 0 {
			_, _, _ = procShowWindow.Call(w.hwnd, swHideWindow)
		}
		w.visible = false
		w.triggerFallback("WebView2 crashed more than 3 times in 5 minutes")
		return
	}
	w.closeController()
	w.initializing = true
	w.createControllerFromEnv()
}

func (w *WebView2Window) triggerFallback(reason string) {
	if w.fallbackSent {
		return
	}
	w.fallbackSent = true
	if w.hwnd != 0 {
		_, _, _ = procShowWindow.Call(w.hwnd, swHideWindow)
	}
	if w.cb.OnFallback != nil {
		go w.cb.OnFallback(reason)
	}
}

func (w *WebView2Window) isAllowedOrigin(raw string) bool {
	if raw == "" || raw == "about:blank" {
		return true
	}
	base := ""
	if w.cb.URL != nil {
		base = w.cb.URL()
	}
	wantOrigin := originOf(base)
	gotOrigin := originOf(raw)
	return wantOrigin != "" && strings.EqualFold(gotOrigin, wantOrigin)
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (w *WebView2Window) openExternal(uri string) error {
	if w.cb.OpenExternal != nil {
		return w.cb.OpenExternal(uri)
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(uri)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

func (w *WebView2Window) closeController() {
	if w.webview != 0 {
		comRelease(w.webview)
		w.webview = 0
	}
	if w.ctrl != 0 {
		comCall0(w.ctrl, 24) // ICoreWebView2Controller::Close
		comRelease(w.ctrl)
		w.ctrl = 0
	}
}

func (w *WebView2Window) setControllerVisible(vis bool) {
	if w.ctrl == 0 {
		return
	}
	v := uintptr(0)
	if vis {
		v = 1
	}
	comCall1(w.ctrl, 4, v) // put_IsVisible
}

func (w *WebView2Window) updateBounds() {
	if w.ctrl == 0 || w.hwnd == 0 {
		return
	}
	var rc winRect
	if ok, _, _ := procGetClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&rc))); ok == 0 {
		return
	}
	_ = putControllerBounds(w.ctrl, rc)
}

func putControllerBounds(ctrl uintptr, rc winRect) uintptr {
	vtbl := (*comVtableObj)(ptrFromAddr(ctrl)).vt
	if runtime.GOARCH == "arm64" {
		w0 := uintptr(uint32(rc.Left)) | (uintptr(uint32(rc.Top)) << 32)
		w1 := uintptr(uint32(rc.Right)) | (uintptr(uint32(rc.Bottom)) << 32)
		hr, _, _ := syscall.SyscallN(vtbl[6], ctrl, w0, w1)
		return hr
	}
	hr, _, _ := syscall.SyscallN(vtbl[6], ctrl, uintptr(unsafe.Pointer(&rc)))
	return hr
}

func getControllerBounds(ctrl uintptr) (winRect, error) {
	var rc winRect
	hr := comCall1(ctrl, 5, uintptr(unsafe.Pointer(&rc)))
	if int32(hr) < 0 {
		return winRect{}, fmt.Errorf("get_Bounds: 0x%08x", uint32(hr))
	}
	return rc, nil
}

// ------------------------------------------------------------ TOCTOU-safe WebView2Loader.dll

func (w *WebView2Window) ensureLoader() error {
	w.loaderMu.Lock()
	defer w.loaderMu.Unlock()
	if w.createEnvProc != 0 && w.getVerProc != 0 {
		return nil
	}
	expected := pinnedWebView2Loader[runtime.GOARCH]
	if expected == "" {
		return fmt.Errorf("unsupported WebView2Loader architecture %s", runtime.GOARCH)
	}
	dir, err := resolveLoaderDirectory()
	if err != nil {
		return err
	}
	dllPath := filepath.Join(dir, "WebView2Loader.dll")
	info, err := os.Lstat(dllPath)
	if err != nil {
		return fmt.Errorf("WebView2Loader.dll missing: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("WebView2Loader.dll must be a regular file, not a symlink")
	}
	resolved, err := filepath.EvalSymlinks(dllPath)
	if err != nil || !strings.EqualFold(filepath.Clean(dllPath), resolved) {
		return errors.New("WebView2Loader.dll path contains a reparse point")
	}
	p, err := windows.UTF16PtrFromString(dllPath)
	if err != nil {
		return err
	}
	// Open without FILE_SHARE_WRITE so bytes cannot mutate between hashing and LoadLibraryEx.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open WebView2Loader.dll: %w", err)
	}
	f := os.NewFile(uintptr(h), dllPath)
	keepFile := false
	defer func() {
		if !keepFile {
			_ = f.Close()
		}
	}()
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return fmt.Errorf("hash WebView2Loader.dll: %w", err)
	}
	got := fmt.Sprintf("%x", digest.Sum(nil))
	if got != expected {
		return fmt.Errorf("WebView2Loader.dll SHA-256 mismatch (%s)", runtime.GOARCH)
	}
	mod, err := windows.LoadLibraryEx(dllPath, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("LoadLibraryEx WebView2Loader.dll: %w", err)
	}
	createEnv, err := windows.GetProcAddress(mod, "CreateCoreWebView2EnvironmentWithOptions")
	if err != nil {
		_ = windows.FreeLibrary(mod)
		return err
	}
	getVer, err := windows.GetProcAddress(mod, "GetAvailableCoreWebView2BrowserVersionString")
	if err != nil {
		_ = windows.FreeLibrary(mod)
		return err
	}
	w.loaderModule = mod
	w.loaderFile = f
	w.createEnvProc = createEnv
	w.getVerProc = getVer
	keepFile = true
	return nil
}

func resolveLoaderDirectory() (string, error) {
	if testing.Testing() {
		if dir := os.Getenv("NETSWITCH_WEBVIEW2_LOADER_DIR"); dir != "" {
			return filepath.Clean(dir), nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func (w *WebView2Window) availableBrowserVersion() (string, error) {
	var verPtr uintptr
	hr, _, _ := syscall.SyscallN(w.getVerProc, 0, uintptr(unsafe.Pointer(&verPtr)))
	if int32(hr) < 0 {
		return "", fmt.Errorf("0x%08x", uint32(hr))
	}
	if verPtr == 0 {
		return "", nil
	}
	return takeCoTaskMemString(verPtr), nil
}

// OpenPairBrowserApp launches Microsoft Edge or Google Chrome in frameless
// --app mode for url (falling back to the default browser via ShellExecute)
// and returns whether an app-mode Chromium browser was started.
func OpenPairBrowserApp(pairURL string) error {
	for _, exe := range chromiumAppBrowsers() {
		cmd := exec.Command(exe, "--app="+pairURL)
		if cmd.Start() == nil {
			go func() { _ = cmd.Wait() }()
			return nil
		}
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	addr, err := windows.UTF16PtrFromString(pairURL)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, addr, nil, nil, windows.SW_SHOWNORMAL)
}

func chromiumAppBrowsers() []string {
	var found []string
	roots := []string{
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramFiles"),
		os.Getenv("LocalAppData"),
	}
	rels := []string{
		`Microsoft\Edge\Application\msedge.exe`,
		`Google\Chrome\Application\chrome.exe`,
		`BraveSoftware\Brave-Browser\Application\brave.exe`,
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		for _, rel := range rels {
			cand := filepath.Join(root, rel)
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				found = append(found, cand)
			}
		}
	}
	return found
}

// ------------------------------------------------------------ Pure-Go COM infrastructure

type comCallbackState struct {
	iid windows.GUID
	fn  func(arg1, arg2 uintptr)
}

// comUnkHeader lives in GlobalAlloc memory so COM refcounts never touch Go GC.
type comUnkHeader struct {
	vtbl uintptr
	ref  int32
	_pad uint32
	id   uint64
}

var (
	comVtblOnce sync.Once
	comVtblPtr  uintptr
	comCBOnce   [4]uintptr
	comMu       sync.Mutex
	comSeq      uint64
	comMap      = map[uint64]*comCallbackState{}
)

func initCOMVtbl() uintptr {
	comVtblOnce.Do(func() {
		comCBOnce[0] = windows.NewCallback(comQueryInterfaceCB)
		comCBOnce[1] = windows.NewCallback(comAddRefCB)
		comCBOnce[2] = windows.NewCallback(comReleaseCB)
		comCBOnce[3] = windows.NewCallback(comInvokeCB)
		mem, _, _ := procGlobalAlloc.Call(gmemFixedZeroInit, 4*unsafe.Sizeof(uintptr(0)))
		if mem != 0 {
			slots := (*[4]uintptr)(ptrFromAddr(mem))
			slots[0] = comCBOnce[0]
			slots[1] = comCBOnce[1]
			slots[2] = comCBOnce[2]
			slots[3] = comCBOnce[3]
			comVtblPtr = mem
		}
	})
	return comVtblPtr
}

type comVtableObj struct{ vt *[64]uintptr }

// ptrFromAddr converts an unmanaged Win32 or COM address supplied as uintptr
// into an unsafe.Pointer without flagging Go's unsafeptr vet rule.
func ptrFromAddr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

func newCOMCallback(iid windows.GUID, fn func(arg1, arg2 uintptr)) uintptr {
	vtbl := initCOMVtbl()
	mem, _, _ := procGlobalAlloc.Call(gmemFixedZeroInit, unsafe.Sizeof(comUnkHeader{}))
	if mem == 0 {
		return 0
	}
	comMu.Lock()
	comSeq++
	id := comSeq
	comMap[id] = &comCallbackState{iid: iid, fn: fn}
	comMu.Unlock()

	hdr := (*comUnkHeader)(ptrFromAddr(mem))
	hdr.vtbl = vtbl
	hdr.ref = 1
	hdr.id = id
	return mem
}

func comQueryInterfaceCB(this uintptr, riidPtr uintptr, ppvPtr uintptr) uintptr {
	if ppvPtr == 0 {
		return hresultInvalidArg
	}
	*(*uintptr)(ptrFromAddr(ppvPtr)) = 0
	if this == 0 || riidPtr == 0 {
		return hresultInvalidArg
	}
	riid := *(*windows.GUID)(ptrFromAddr(riidPtr))
	hdr := (*comUnkHeader)(ptrFromAddr(this))
	comMu.Lock()
	st := comMap[hdr.id]
	comMu.Unlock()
	if riid == iidIUnknown || (st != nil && riid == st.iid) {
		comAddRefCB(this)
		*(*uintptr)(ptrFromAddr(ppvPtr)) = this
		return 0
	}
	return hresultNoInterface
}

func comAddRefCB(this uintptr) uintptr {
	if this == 0 {
		return 0
	}
	hdr := (*comUnkHeader)(ptrFromAddr(this))
	return uintptr(atomic.AddInt32(&hdr.ref, 1))
}

func comReleaseCB(this uintptr) uintptr {
	if this == 0 {
		return 0
	}
	hdr := (*comUnkHeader)(ptrFromAddr(this))
	rem := atomic.AddInt32(&hdr.ref, -1)
	if rem == 0 {
		comMu.Lock()
		delete(comMap, hdr.id)
		comMu.Unlock()
		_, _, _ = procGlobalFree.Call(this)
	}
	return uintptr(uint32(rem))
}

func comInvokeCB(this uintptr, arg1 uintptr, arg2 uintptr) uintptr {
	if this == 0 {
		return 0
	}
	hdr := (*comUnkHeader)(ptrFromAddr(this))
	comMu.Lock()
	st := comMap[hdr.id]
	comMu.Unlock()
	if st != nil && st.fn != nil {
		st.fn(arg1, arg2)
	}
	return 0
}

func comCall0(obj uintptr, slot int) uintptr {
	vtbl := (*comVtableObj)(ptrFromAddr(obj)).vt
	hr, _, _ := syscall.SyscallN(vtbl[slot], obj)
	return hr
}

//go:uintptrescapes
func comCall1(obj uintptr, slot int, a1 uintptr) uintptr {
	vtbl := (*comVtableObj)(ptrFromAddr(obj)).vt
	hr, _, _ := syscall.SyscallN(vtbl[slot], obj, a1)
	return hr
}

//go:uintptrescapes
func comCall2(obj uintptr, slot int, a1, a2 uintptr) uintptr {
	vtbl := (*comVtableObj)(ptrFromAddr(obj)).vt
	hr, _, _ := syscall.SyscallN(vtbl[slot], obj, a1, a2)
	return hr
}

func comQueryInterface(obj uintptr, iid windows.GUID) uintptr {
	if obj == 0 {
		return 0
	}
	var out uintptr
	hr := comCall2(obj, 0, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 {
		return 0
	}
	return out
}

func comAddRefIfNonZero(obj uintptr) {
	if obj != 0 {
		comCall0(obj, 1)
	}
}

func comRelease(obj uintptr) {
	if obj != 0 {
		comCall0(obj, 2)
	}
}

func comReleaseIfNonZero(obj uintptr) {
	if obj != 0 {
		comCall0(obj, 2)
	}
}

func takeCoTaskMemString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	defer func() { _, _, _ = procCoTaskMemFree.Call(ptr) }()
	s := windows.UTF16PtrToString((*uint16)(ptrFromAddr(ptr)))
	return s
}

func createWindowDefaultIcon(size int) (uintptr, error) {
	return CreateHIcon(desktop.WaitingTray(), size)
}
