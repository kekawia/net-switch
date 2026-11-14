//go:build windows

package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/AyoubAchour/net-switch/internal/desktop"
	"github.com/AyoubAchour/net-switch/internal/desktop/winui"
)

type windowsDesktopUI struct {
	cb desktop.UICallbacks

	mu           sync.Mutex
	baseURL      string
	token        string
	owner        string
	reachable    bool
	quitting     bool
	offer        *[2]string
	settings     desktop.TraySettings
	settingsPath string
	notifier     desktop.EventNotifier
	closed       bool
	pairBusy     bool

	loop   *winui.Loop
	tray   *winui.TrayIcon
	flyout *winui.FlyoutWindow
	wv     *winui.WebView2Window
}

// New starts the Windows desktop tray, flyout, and WebView2 host shell.
func New(cb desktop.UICallbacks) desktop.UI {
	settingsPath, _ := desktop.DefaultTraySettingsPath()
	cfg := desktop.TraySettings{LineNotifications: true}
	if settingsPath != "" {
		cfg = desktop.LoadTraySettings(settingsPath)
	}
	loop, err := winui.StartLoop("Net Switch")
	if err != nil {
		fmt.Fprintln(os.Stderr, "desktop UI loop unavailable:", err)
		return desktop.NoopUI{}
	}

	u := &windowsDesktopUI{
		cb:           cb,
		settings:     cfg,
		settingsPath: settingsPath,
		loop:         loop,
	}

	flyout, err := winui.NewFlyoutWindow(loop, u.handleFlyoutAction)
	if err == nil {
		u.flyout = flyout
	}
	tray, err := winui.NewTrayIcon(loop, winui.TrayCallbacks{
		NotificationsEnabled: func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.settings.LineNotifications
		},
		UpdateOffer: func() *[2]string {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.offer
		},
		Unreachable: func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return !u.reachable
		},
		Quitting: func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.quitting
		},
		OnToggleFlyout: func(anchorX, anchorY int32) {
			if u.flyout != nil {
				u.flyout.ToggleAt(anchorX, anchorY)
			} else {
				u.ShowWindow("")
			}
		},
		FlyoutDismissInfo: func() (time.Time, int32, int32) {
			if u.flyout != nil {
				return u.flyout.DismissInfo()
			}
			return time.Time{}, 0, 0
		},
		OnOpenWindow: func(appKey string) {
			u.ShowWindow(appKey)
		},
		OnToggleNotices: func() {
			u.mu.Lock()
			u.settings.LineNotifications = !u.settings.LineNotifications
			s := u.settings
			p := u.settingsPath
			u.mu.Unlock()
			if p != "" {
				_ = s.Save(p)
			}
		},
		OnOpenUpdate: func(uri string) {
			if !strings.HasPrefix(uri, desktop.InstallerPrefix) {
				return
			}
			openShellURI(uri)
		},
		OnRemoveIcon: func() {
			u.mu.Lock()
			tray := u.tray
			u.tray = nil
			u.mu.Unlock()
			if tray != nil {
				tray.Close()
			}
		},
		OnQuit: func() {
			if u.cb.Quit != nil {
				u.cb.Quit()
			}
		},
	})
	if err == nil {
		u.tray = tray
	}

	userDataDir := ""
	if cacheDir, cacheErr := os.UserCacheDir(); cacheErr == nil && cacheDir != "" {
		userDataDir = filepath.Join(cacheDir, "Net Switch", "WebView2")
	}
	u.wv = winui.NewWebView2Window(loop, winui.WebView2Callbacks{
		URL: func() string {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.baseURL
		},
		Token: func() string {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.token
		},
		OnRefreshToken: cb.RefreshToken,
		OnQuit:         cb.Quit,
		OnFallback: func(string) {
			go u.openPairFallback()
		},
		UserDataDir: userDataDir,
	})
	return u
}

func (u *windowsDesktopUI) handleFlyoutAction(act winui.FlyoutAction) {
	switch {
	case act.Key == "open" || act.Key == "more" || act.Key == "all":
		u.ShowWindow("")
	case strings.HasPrefix(act.Key, "change:"):
		u.ShowWindow(strings.TrimPrefix(act.Key, "change:"))
	case act.Key == "quit":
		if u.cb.Quit != nil {
			u.cb.Quit()
		}
	case act.Endpoint == "/api/routing" && u.cb.ToggleRouting != nil:
		on, _ := act.Body["on"].(bool)
		u.cb.ToggleRouting(on)
	case act.Endpoint == "/api/combine" && u.cb.ToggleCombine != nil:
		on, _ := act.Body["on"].(bool)
		u.cb.ToggleCombine(on)
	case act.Endpoint == "/api/app-line" && u.cb.SetAppLine != nil:
		target, _ := act.Body["path"].(string)
		var linePtr *string
		if s, ok := act.Body["line"].(string); ok && s != "" {
			linePtr = &s
		}
		if target != "" {
			u.cb.SetAppLine(target, linePtr)
		}
	}
}

func (u *windowsDesktopUI) SetSession(baseURL, token, owner string) {
	u.mu.Lock()
	u.baseURL = baseURL
	u.token = token
	u.owner = owner
	wv := u.wv
	u.mu.Unlock()
	if wv != nil {
		wv.NotifyEndpointUpdated()
	}
}

func (u *windowsDesktopUI) ShowWindow(appKey string) {
	u.mu.Lock()
	wv := u.wv
	closed := u.closed
	u.mu.Unlock()
	if closed {
		return
	}
	if wv == nil {
		go u.openPairFallback()
		return
	}
	if err := wv.Open(appKey); err != nil {
		go u.openPairFallback()
	}
}

func (u *windowsDesktopUI) openPairFallback() {
	if u.cb.OpenPair == nil {
		return
	}
	u.mu.Lock()
	if u.closed || u.pairBusy {
		u.mu.Unlock()
		return
	}
	u.pairBusy = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.pairBusy = false
		u.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pairURL, code, _, err := u.cb.OpenPair(ctx)
	if err != nil || pairURL == "" {
		return
	}
	if err := winui.OpenPairBrowserApp(pairURL); err != nil {
		return
	}
	if code != "" {
		u.Notify("Connect to Net Switch", "Enter this code in Net Switch: "+code+" (expires in two minutes).", false)
	}
}

func (u *windowsDesktopUI) UpdateState(raw map[string]any, reachable bool) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.reachable = reachable
	quitting := u.quitting
	tray := u.tray
	flyout := u.flyout
	var trayView desktop.TrayView
	var flyoutView desktop.FlyoutView
	if quitting {
		trayView = desktop.QuittingTray()
		flyoutView = desktop.UnavailableFlyout("Net Switch is quitting\u2026")
	} else if !reachable || raw == nil {
		u.offer = nil
		trayView = desktop.UnreachableTray(false)
		flyoutView = desktop.UnavailableFlyout("Net Switch isn\u2019t responding.")
	} else {
		u.offer = desktop.UpdateOffer(raw)
		trayView = desktop.TrayFromState(raw)
		flyoutView = desktop.FlyoutFromState(raw)
		events, hasEvents := desktop.EventsFromState(raw)
		u.notifier.Read(events, hasEvents, u.settings.LineNotifications)
		if notice := u.notifier.Next(time.Now()); notice != nil && tray != nil {
			defer func(title, text string, warn bool) {
				_ = tray.Balloon(title, text, warn)
			}(notice.Title, notice.Text, notice.Warning)
		}
	}
	u.mu.Unlock()

	if tray != nil {
		_ = tray.Update(trayView)
	}
	if flyout != nil {
		flyout.SetView(flyoutView)
	}
}

func (u *windowsDesktopUI) SetActionFeedback(pendingKey, errMsg string) {
	u.mu.Lock()
	flyout := u.flyout
	quitting := u.quitting
	closed := u.closed
	u.mu.Unlock()
	if closed || flyout == nil {
		return
	}
	flyout.SetFeedback(pendingKey, errMsg, quitting)
}

func (u *windowsDesktopUI) SetQuitting() {
	u.mu.Lock()
	u.quitting = true
	tray := u.tray
	flyout := u.flyout
	u.mu.Unlock()
	if tray != nil {
		_ = tray.Update(desktop.QuittingTray())
	}
	if flyout != nil {
		flyout.SetFeedback("", "", true)
	}
}

func (u *windowsDesktopUI) Notify(title, body string, warning bool) {
	u.mu.Lock()
	tray := u.tray
	closed := u.closed
	u.mu.Unlock()
	if closed {
		return
	}
	if tray != nil {
		_ = tray.Balloon(title, body, warning)
		return
	}
	if u.cb.FallbackStatus != nil {
		_ = u.cb.FallbackStatus(body)
	}
}

func (u *windowsDesktopUI) Close() {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	wv := u.wv
	flyout := u.flyout
	tray := u.tray
	loop := u.loop
	u.wv = nil
	u.flyout = nil
	u.tray = nil
	u.loop = nil
	u.mu.Unlock()

	if wv != nil {
		wv.Close()
	}
	if flyout != nil {
		flyout.Close()
	}
	if tray != nil {
		tray.Close()
	}
	if loop != nil {
		loop.Close()
	}
}

func openShellURI(uri string) {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return
	}
	addr, err := windows.UTF16PtrFromString(uri)
	if err != nil {
		return
	}
	_ = windows.ShellExecute(0, verb, addr, nil, nil, windows.SW_SHOWNORMAL)
}
