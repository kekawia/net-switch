//go:build linux

package linuxui

import (
	"context"
	"fmt"
	"sync"

	"fyne.io/systray"
	"github.com/AyoubAchour/net-switch/internal/desktop"
)

// Callbacks handle user selections from the Linux system tray menu.
type Callbacks struct {
	NotificationsEnabled func() bool
	UpdateOffer          func() *[2]string
	RoutingWanted        func() bool
	CombineActive        func() bool
	LineCount            func() int
	OnOpenWindow         func()
	OnToggleRouting      func(wantOn bool)
	OnToggleCombine      func(wantOn bool)
	OnToggleNotices      func()
	OnOpenUpdate         func(url string)
	OnRemoveIcon         func()
	OnQuit               func()
}

// Shell owns the Linux StatusNotifierItem tray integration and desktop notices.
// When no session D-Bus is present (headless services/tests), Shell degrades
// cleanly into a no-op controller with HasTray() == false.
type Shell struct {
	mu       sync.Mutex
	cb       Callbacks
	headless bool
	hasTray  bool
	closed   bool
	hidden   bool

	endFn    func()
	done     chan struct{}
	lastSig  string
	lastView desktop.TrayView

	mStatus  *systray.MenuItem
	mHealth  *systray.MenuItem
	mOpen    *systray.MenuItem
	mRouting *systray.MenuItem
	mCombine *systray.MenuItem
	mNotices *systray.MenuItem
	mUpdate  *systray.MenuItem
	mRemove  *systray.MenuItem
	mQuit    *systray.MenuItem
}

// StartShell initializes the Linux tray icon if a session D-Bus is reachable.
// Headless runs without DBUS_SESSION_BUS_ADDRESS return a working no-op Shell.
func StartShell(cb Callbacks) *Shell {
	s := &Shell{
		cb:       cb,
		lastView: desktop.WaitingTray(),
		done:     make(chan struct{}),
	}
	if !CanConnectSessionBus(context.Background()) {
		s.headless = true
		close(s.done)
		return s
	}

	s.hasTray = HasStatusNotifierWatcher(context.Background())
	ready := make(chan struct{})
	startFn, endFn := systray.RunWithExternalLoop(
		func() {
			s.buildMenu()
			close(ready)
		},
		func() {},
	)
	s.endFn = endFn
	startFn()
	<-ready
	return s
}

// HasTray reports whether a StatusNotifierWatcher host was detected when the
// shell started (false in headless or non-D-Bus sessions).
func (s *Shell) HasTray() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasTray && !s.headless
}

func (s *Shell) buildMenu() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if png, err := desktop.PaintIconPNG(s.lastView, 64); err == nil && len(png) > 0 {
		systray.SetIcon(png)
		s.lastSig = desktop.IconSignature(s.lastView)
	}
	systray.SetTitle("Net Switch")
	systray.SetTooltip(desktop.Tooltip(s.lastView))
	systray.SetOnTapped(func() {
		if s.cb.OnOpenWindow != nil {
			s.cb.OnOpenWindow()
		}
	})

	s.mStatus = systray.AddMenuItem("Net Switch", "")
	s.mStatus.Disable()
	s.mHealth = systray.AddMenuItem("", "")
	s.mHealth.Disable()
	s.mHealth.Hide()

	systray.AddSeparator()
	s.mOpen = systray.AddMenuItem("Open Net Switch", "Open the Net Switch window")
	s.mRouting = systray.AddMenuItem("Turn on routing", "Turn routing on or off")
	s.mCombine = systray.AddMenuItemCheckbox("Combine lines", "Split new connections across healthy lines", false)
	s.mNotices = systray.AddMenuItemCheckbox("Notifications", "Show notifications when a line changes", true)
	s.mUpdate = systray.AddMenuItem("Update available", "Download the latest release")
	s.mUpdate.Hide()

	systray.AddSeparator()
	s.mRemove = systray.AddMenuItem("Remove tray icon", "Hide the tray icon without stopping Net Switch")
	s.mQuit = systray.AddMenuItem("Quit Net Switch", "Turn off routing and quit Net Switch")

	if s.cb.NotificationsEnabled != nil && !s.cb.NotificationsEnabled() {
		s.mNotices.Uncheck()
	}

	go s.handleClicks()
}

func (s *Shell) handleClicks() {
	for {
		select {
		case <-s.done:
			return
		case _, ok := <-s.mOpen.ClickedCh:
			if !ok {
				return
			}
			if s.cb.OnOpenWindow != nil {
				s.cb.OnOpenWindow()
			}
		case _, ok := <-s.mRouting.ClickedCh:
			if !ok {
				return
			}
			if s.cb.OnToggleRouting != nil {
				wantOn := true
				if s.cb.RoutingWanted != nil {
					wantOn = !s.cb.RoutingWanted()
				}
				s.cb.OnToggleRouting(wantOn)
			}
		case _, ok := <-s.mCombine.ClickedCh:
			if !ok {
				return
			}
			if s.cb.OnToggleCombine != nil {
				wantOn := true
				if s.cb.CombineActive != nil {
					wantOn = !s.cb.CombineActive()
				}
				s.cb.OnToggleCombine(wantOn)
			}
		case _, ok := <-s.mNotices.ClickedCh:
			if !ok {
				return
			}
			if s.cb.OnToggleNotices != nil {
				s.cb.OnToggleNotices()
			}
			if s.cb.NotificationsEnabled != nil {
				enabled := s.cb.NotificationsEnabled()
				s.mu.Lock()
				if !s.closed && !s.hidden && s.mNotices != nil {
					if enabled {
						s.mNotices.Check()
					} else {
						s.mNotices.Uncheck()
					}
				}
				s.mu.Unlock()
			}
		case _, ok := <-s.mUpdate.ClickedCh:
			if !ok {
				return
			}
			if s.cb.UpdateOffer != nil && s.cb.OnOpenUpdate != nil {
				if offer := s.cb.UpdateOffer(); offer != nil {
					s.cb.OnOpenUpdate(offer[1])
				}
			}
		case _, ok := <-s.mRemove.ClickedCh:
			if !ok {
				return
			}
			s.mu.Lock()
			s.hidden = true
			s.mu.Unlock()
			if s.cb.OnRemoveIcon != nil {
				s.cb.OnRemoveIcon()
			}
			s.Close()
		case _, ok := <-s.mQuit.ClickedCh:
			if !ok {
				return
			}
			if s.cb.OnQuit != nil {
				s.cb.OnQuit()
			}
		}
	}
}

// Update refreshes the tray icon, tooltip, and menu labels for view and raw state.
func (s *Shell) Update(view desktop.TrayView, flyout desktop.FlyoutView) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.headless || s.closed || s.hidden {
		return
	}
	s.lastView = view
	sig := desktop.IconSignature(view)
	if sig != s.lastSig {
		if png, err := desktop.PaintIconPNG(view, 64); err == nil && len(png) > 0 {
			systray.SetIcon(png)
		}
		s.lastSig = sig
	}
	systray.SetTooltip(desktop.Tooltip(view))

	if s.mStatus != nil {
		headline := view.Status
		if headline == "" {
			headline = "Net Switch"
		}
		s.mStatus.SetTitle(headline)
	}
	if s.mHealth != nil {
		if flyout.Health != "" {
			s.mHealth.SetTitle(flyout.Health)
			s.mHealth.Show()
		} else {
			s.mHealth.Hide()
		}
	}
	if s.mRouting != nil {
		if s.cb.RoutingWanted != nil && s.cb.RoutingWanted() {
			s.mRouting.SetTitle("Turn off routing")
		} else {
			s.mRouting.SetTitle("Turn on routing")
		}
	}
	if s.mCombine != nil {
		if s.cb.LineCount != nil && s.cb.LineCount() >= 2 {
			s.mCombine.Show()
			if s.cb.CombineActive != nil && s.cb.CombineActive() {
				s.mCombine.Check()
			} else {
				s.mCombine.Uncheck()
			}
		} else {
			s.mCombine.Hide()
		}
	}
	if s.mNotices != nil && s.cb.NotificationsEnabled != nil {
		if s.cb.NotificationsEnabled() {
			s.mNotices.Check()
		} else {
			s.mNotices.Uncheck()
		}
	}
	if s.mUpdate != nil && s.cb.UpdateOffer != nil {
		if offer := s.cb.UpdateOffer(); offer != nil {
			s.mUpdate.SetTitle(fmt.Sprintf("Download Net Switch v%s", offer[0]))
			s.mUpdate.Show()
		} else {
			s.mUpdate.Hide()
		}
	}
}

// Notify delivers a desktop notification when not running headless.
func (s *Shell) Notify(ctx context.Context, title, body string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	headless := s.headless
	s.mu.Unlock()
	if headless {
		return
	}
	_ = SendNotification(ctx, title, body, 8000)
}

// Close tears down the tray icon and D-Bus loop cleanly.
func (s *Shell) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	headless := s.headless
	endFn := s.endFn
	s.mu.Unlock()

	if !headless {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
		if endFn != nil {
			endFn()
		}
	}
}
