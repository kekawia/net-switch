//go:build linux

package host

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/desktop"
	"github.com/AyoubAchour/net-switch/internal/desktop/linuxui"
)

type linuxDesktopUI struct {
	cb desktop.UICallbacks

	mu            sync.Mutex
	routingWanted bool
	combineActive bool
	lineCount     int
	offer         *[2]string
	settings      desktop.TraySettings
	settingsPath  string
	notifier      desktop.EventNotifier
	quitting      bool
	closed        bool
	shell         *linuxui.Shell
}

// New starts the Linux StatusNotifier tray, D-Bus notifier, and app launcher shell.
func New(cb desktop.UICallbacks) desktop.UI {
	settingsPath, _ := desktop.DefaultTraySettingsPath()
	cfg := desktop.TraySettings{LineNotifications: true}
	if settingsPath != "" {
		cfg = desktop.LoadTraySettings(settingsPath)
	}
	u := &linuxDesktopUI{
		cb:           cb,
		settings:     cfg,
		settingsPath: settingsPath,
	}
	u.shell = linuxui.StartShell(linuxui.Callbacks{
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
		RoutingWanted: func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.routingWanted
		},
		CombineActive: func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.combineActive
		},
		LineCount: func() int {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.lineCount
		},
		OnOpenWindow: func() {
			u.ShowWindow("")
		},
		OnToggleRouting: func(wantOn bool) {
			if u.cb.ToggleRouting != nil {
				u.cb.ToggleRouting(wantOn)
			}
		},
		OnToggleCombine: func(wantOn bool) {
			if u.cb.ToggleCombine != nil {
				u.cb.ToggleCombine(wantOn)
			}
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
			cmd := exec.Command("xdg-open", uri)
			if cmd.Start() == nil {
				go func() { _ = cmd.Wait() }()
			}
		},
		OnQuit: func() {
			if u.cb.Quit != nil {
				u.cb.Quit()
			}
		},
	})
	return u
}

func (u *linuxDesktopUI) SetSession(_, _, _ string) {}

func (u *linuxDesktopUI) ShowWindow(_ string) {
	if u.cb.OpenPair == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pairURL, code, owner, err := u.cb.OpenPair(ctx)
		if err != nil || pairURL == "" {
			return
		}
		_ = linuxui.OpenAppWindow(ctx, pairURL, code, owner)
	}()
}

func (u *linuxDesktopUI) UpdateState(raw map[string]any, reachable bool) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	quitting := u.quitting
	shell := u.shell
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
		u.routingWanted = flyoutView.RoutingWanted
		u.combineActive = flyoutView.CombineOn
		u.lineCount = len(trayView.Lines)
		events, hasEvents := desktop.EventsFromState(raw)
		u.notifier.Read(events, hasEvents, u.settings.LineNotifications)
		if notice := u.notifier.Next(time.Now()); notice != nil && shell != nil {
			defer func(title, text string) {
				shell.Notify(context.Background(), title, text)
			}(notice.Title, notice.Text)
		}
	}
	u.mu.Unlock()

	if shell != nil {
		shell.Update(trayView, flyoutView)
	}
}

func (u *linuxDesktopUI) SetActionFeedback(string, string) {}

func (u *linuxDesktopUI) SetQuitting() {
	u.mu.Lock()
	u.quitting = true
	shell := u.shell
	u.mu.Unlock()
	if shell != nil {
		shell.Update(desktop.QuittingTray(), desktop.UnavailableFlyout("Net Switch is quitting\u2026"))
	}
}

func (u *linuxDesktopUI) Notify(title, body string, _ bool) {
	u.mu.Lock()
	shell := u.shell
	closed := u.closed
	u.mu.Unlock()
	if closed || shell == nil {
		return
	}
	shell.Notify(context.Background(), title, body)
}

func (u *linuxDesktopUI) Close() {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	shell := u.shell
	u.shell = nil
	u.mu.Unlock()
	if shell != nil {
		shell.Close()
	}
}
