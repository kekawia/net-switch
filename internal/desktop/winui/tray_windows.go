//go:build windows

package winui

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/desktop"
)

const (
	trayIconID         = 0x4E53
	notifyIconVersion4 = 4

	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nimSetVersion = 0x00000004

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	nifShowTip = 0x00000080

	niifInfo    = 0x00000001
	niifWarning = 0x00000002

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	mfChecked   = 0x00000008
	mfUnchecked = 0x00000000
	mfGrayed    = 0x00000001
	mfDisabled  = 0x00000002

	tpmRightButton = 0x0002
	tpmLeftAlign   = 0x0000
	tpmRightAlign  = 0x0008
	tpmBottomAlign = 0x0020

	cmdTrayOpen        = 1
	cmdTrayQuit        = 2
	cmdTrayRemove      = 3
	cmdTrayUpdate      = 4
	cmdTrayLineNotices = 5
)

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

// TrayCallbacks handles user interactions from the system tray icon and menu.
type TrayCallbacks struct {
	NotificationsEnabled func() bool
	UpdateOffer          func() *[2]string
	Unreachable          func() bool
	Quitting             func() bool
	OnToggleFlyout       func(anchorX, anchorY int32)
	FlyoutDismissInfo    func() (time.Time, int32, int32)
	OnOpenWindow         func(appKey string)
	OnToggleNotices      func()
	OnOpenUpdate         func(url string)
	OnRemoveIcon         func()
	OnQuit               func()
}

// TrayIcon owns the Win32 Shell_NotifyIconW notification-area icon, menu, and
// balloon notifications on a Loop's UI thread.
type TrayIcon struct {
	loop      *Loop
	cb        TrayCallbacks
	view      desktop.TrayView
	hIcon     uintptr
	lastSig   string
	lastSize  int
	added     bool
	closed    bool
	lastOffer *[2]string
}

// NewTrayIcon registers the notification icon on loop's UI thread.
func NewTrayIcon(loop *Loop, cb TrayCallbacks) (*TrayIcon, error) {
	if loop == nil {
		return nil, fmt.Errorf("winui tray requires an active Loop")
	}
	t := &TrayIcon{
		loop: loop,
		cb:   cb,
		view: desktop.WaitingTray(),
	}
	err := loop.Do(func() error {
		loop.onTrayMsg = t.handleTrayMsg
		loop.onTaskbar = t.handleTaskbarCreated
		loop.onCommand = t.handleCommand
		return t.installOrRefresh(true)
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Update refreshes the tray icon bitmap and tooltip for view.
func (t *TrayIcon) Update(view desktop.TrayView) error {
	if t == nil || t.loop == nil {
		return nil
	}
	return t.loop.Do(func() error {
		if t.closed {
			return nil
		}
		t.view = view
		return t.installOrRefresh(false)
	})
}

// Balloon shows a Windows notification balloon tied to the tray icon.
func (t *TrayIcon) Balloon(title, body string, warning bool) error {
	if t == nil || t.loop == nil {
		return nil
	}
	return t.loop.Do(func() error {
		if t.closed || !t.added || t.loop.trayHwnd == 0 {
			return nil
		}
		var nid notifyIconDataW
		nid.cbSize = uint32(unsafe.Sizeof(nid))
		nid.hWnd = t.loop.trayHwnd
		nid.uID = trayIconID
		nid.uFlags = nifInfo | nifShowTip
		if warning {
			nid.dwInfoFlags = niifWarning
		} else {
			nid.dwInfoFlags = niifInfo
		}
		copyUTF16Z(nid.szInfoTitle[:], title)
		copyUTF16Z(nid.szInfo[:], body)
		_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
		return nil
	})
}

// Close removes the tray icon and releases its GDI HICON handle.
func (t *TrayIcon) Close() {
	if t == nil || t.loop == nil {
		return
	}
	_ = t.loop.Do(func() error {
		if t.closed {
			return nil
		}
		t.closed = true
		t.loop.onTrayMsg = nil
		t.loop.onTaskbar = nil
		t.loop.onCommand = nil
		if t.added && t.loop.trayHwnd != 0 {
			var nid notifyIconDataW
			nid.cbSize = uint32(unsafe.Sizeof(nid))
			nid.hWnd = t.loop.trayHwnd
			nid.uID = trayIconID
			_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
			t.added = false
		}
		DestroyHIcon(t.hIcon)
		t.hIcon = 0
		return nil
	})
}

// Added reports whether Shell_NotifyIconW(NIM_ADD) is currently active.
func (t *TrayIcon) Added() bool {
	if t == nil || t.loop == nil {
		return false
	}
	var added bool
	_ = t.loop.Do(func() error {
		added = t.added
		return nil
	})
	return added
}

func (t *TrayIcon) handleTaskbarCreated() {
	if t.closed {
		return
	}
	t.added = false
	_ = t.installOrRefresh(true)
}

func (t *TrayIcon) installOrRefresh(forceAdd bool) error {
	if t.closed || t.loop.trayHwnd == 0 {
		return nil
	}
	iconSize := trayIconSize()
	sig := desktop.IconSignature(t.view)
	if t.hIcon == 0 || sig != t.lastSig || iconSize != t.lastSize {
		next, err := CreateHIcon(t.view, iconSize)
		if err != nil {
			return err
		}
		DestroyHIcon(t.hIcon)
		t.hIcon = next
		t.lastSig = sig
		t.lastSize = iconSize
	}

	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = t.loop.trayHwnd
	nid.uID = trayIconID
	nid.uFlags = nifMessage | nifIcon | nifTip | nifShowTip
	nid.uCallbackMessage = wmTrayCallback
	nid.hIcon = t.hIcon
	copyUTF16Z(nid.szTip[:], desktop.Tooltip(t.view))

	if !t.added || forceAdd {
		ok, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		if ok == 0 {
			// Explorer taskbar may not exist yet (or may be restarting); TaskbarCreated recovers.
			t.added = false
			return nil
		}
		t.added = true
		var ver notifyIconDataW
		ver.cbSize = uint32(unsafe.Sizeof(ver))
		ver.hWnd = t.loop.trayHwnd
		ver.uID = trayIconID
		ver.uVersion = notifyIconVersion4
		_, _, _ = procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&ver)))
		return nil
	}
	ok, _, _ := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	if ok == 0 {
		// Explorer may have dropped our icon silently; try re-adding cleanly.
		ok, _, _ = procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		if ok != 0 {
			t.added = true
			var ver notifyIconDataW
			ver.cbSize = uint32(unsafe.Sizeof(ver))
			ver.hWnd = t.loop.trayHwnd
			ver.uID = trayIconID
			ver.uVersion = notifyIconVersion4
			_, _, _ = procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&ver)))
		} else {
			t.added = false
		}
	}
	return nil
}

func (t *TrayIcon) handleTrayMsg(wParam, lParam uintptr) {
	if t.closed {
		return
	}
	ev := uint32(lParam & 0xFFFF)
	anchor := winPoint{
		X: int32(int16(wParam & 0xFFFF)),
		Y: int32(int16((wParam >> 16) & 0xFFFF)),
	}
	if anchor.X == 0 && anchor.Y == 0 {
		_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&anchor)))
	}
	switch ev {
	case wmLButtonUp, ninSelect, ninKeySelect:
		if t.recentlyDismissedAt(anchor) {
			return
		}
		if t.cb.OnToggleFlyout != nil {
			t.cb.OnToggleFlyout(anchor.X, anchor.Y)
		} else if t.cb.OnOpenWindow != nil {
			t.cb.OnOpenWindow("")
		}
	case ninBalloonClick:
		if t.cb.OnOpenWindow != nil {
			t.cb.OnOpenWindow("")
		}
	case wmContextMenu, 0x0205 /* WM_RBUTTONUP */ :
		t.showContextMenu(anchor)
	}
}

func (t *TrayIcon) recentlyDismissedAt(pt winPoint) bool {
	if t.cb.FlyoutDismissInfo == nil {
		return false
	}
	dismissedAt, dx, dy := t.cb.FlyoutDismissInfo()
	if dismissedAt.IsZero() {
		return false
	}
	ms := 500
	if dct, _, _ := procGetDoubleClickTime.Call(); dct > 500 && dct < 5000 {
		ms = int(dct)
	}
	if time.Since(dismissedAt) > time.Duration(ms)*time.Millisecond {
		return false
	}
	scale := scaleAtPoint(pt)
	tol := int32(math.Round(6 * scale))
	if abs32(pt.X-dx) <= tol && abs32(pt.Y-dy) <= tol {
		return true
	}
	return false
}

func (t *TrayIcon) showContextMenu(anchor winPoint) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer func() { _, _, _ = procDestroyMenu.Call(menu) }()

	appendMenu := func(flags uintptr, id uintptr, label string) {
		u := utf16.Encode([]rune(strings.ReplaceAll(label, "\x00", "")))
		u = append(u, 0)
		_, _, _ = procAppendMenuW.Call(menu, flags, id, uintptr(unsafe.Pointer(&u[0])))
		runtime.KeepAlive(u)
	}
	appendMenu(mfString, cmdTrayOpen, "Open Net Switch")
	_, _, _ = procSetMenuDefaultItem.Call(menu, cmdTrayOpen, 0)

	t.lastOffer = nil
	if t.cb.UpdateOffer != nil {
		if offer := t.cb.UpdateOffer(); offer != nil {
			t.lastOffer = offer
			appendMenu(mfString, cmdTrayUpdate, "Download Net Switch "+offer[0])
		}
	}
	_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)

	noticesEnabled := true
	if t.cb.NotificationsEnabled != nil {
		noticesEnabled = t.cb.NotificationsEnabled()
	}
	checkFlag := uintptr(mfUnchecked)
	if noticesEnabled {
		checkFlag = mfChecked
	}
	appendMenu(mfString|checkFlag, cmdTrayLineNotices, "Show line notifications")
	_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)

	quitting := t.cb.Quitting != nil && t.cb.Quitting()
	unreachable := t.cb.Unreachable != nil && t.cb.Unreachable()
	switch {
	case quitting:
		appendMenu(mfString|mfGrayed|mfDisabled, 0, "Quitting\u2026")
	case unreachable:
		appendMenu(mfString, cmdTrayRemove, "Remove this icon")
	default:
		appendMenu(mfString, cmdTrayQuit, "Quit Net Switch")
	}

	var pt winPoint
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	if pt.X == 0 && pt.Y == 0 {
		pt = anchor
	}
	flags := uintptr(tpmRightButton | tpmBottomAlign | tpmLeftAlign)
	if align, _, _ := procGetSystemMetrics.Call(smMenuDropAlign); align != 0 {
		flags = uintptr(tpmRightButton | tpmBottomAlign | tpmRightAlign)
	}
	_, _, _ = procSetForegroundWindow.Call(t.loop.trayHwnd)
	_, _, _ = procTrackPopupMenuEx.Call(menu, flags, uintptr(pt.X), uintptr(pt.Y), t.loop.trayHwnd, 0)
	_, _, _ = procPostMessageW.Call(t.loop.trayHwnd, 0, 0, 0)
}

func (t *TrayIcon) handleCommand(id uint16) {
	switch id {
	case cmdTrayOpen:
		if t.cb.OnOpenWindow != nil {
			t.cb.OnOpenWindow("")
		}
	case cmdTrayUpdate:
		if t.lastOffer != nil && t.cb.OnOpenUpdate != nil {
			t.cb.OnOpenUpdate(t.lastOffer[1])
		}
	case cmdTrayLineNotices:
		if t.cb.OnToggleNotices != nil {
			t.cb.OnToggleNotices()
		}
	case cmdTrayRemove:
		if t.cb.OnRemoveIcon != nil {
			t.cb.OnRemoveIcon()
		}
	case cmdTrayQuit:
		if t.cb.OnQuit != nil {
			t.cb.OnQuit()
		}
	}
}

func trayIconSize() int {
	cx, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	n := int(cx)
	if n < 16 {
		return 16
	}
	if n > 64 {
		return 64
	}
	return n
}

func copyUTF16Z(dst []uint16, s string) {
	for i := range dst {
		dst[i] = 0
	}
	if len(dst) <= 1 || s == "" {
		return
	}
	encoded := utf16.Encode([]rune(s))
	limit := len(dst) - 1
	if len(encoded) > limit {
		encoded = encoded[:limit]
	}
	copy(dst, encoded)
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}
