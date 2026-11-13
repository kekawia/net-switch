//go:build windows

// Package winui implements the native Windows tray icon, DWM flyout, and
// hardened WebView2 window for Net Switch without cgo.
package winui

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmDestroy       = 0x0002
	wmSize          = 0x0005
	wmActivate      = 0x0006
	wmClose         = 0x0010
	wmQuit          = 0x0012
	wmEndSession    = 0x0016
	wmEraseBkgnd    = 0x0014
	wmPaint         = 0x000F
	wmGetMinMaxInfo = 0x0024
	wmCommand       = 0x0111
	wmTimer         = 0x0113
	wmMouseMove     = 0x0200
	wmLButtonDown   = 0x0201
	wmLButtonUp     = 0x0202
	wmMouseLeave    = 0x02A3
	wmKeyDown       = 0x0100
	wmSysKeyDown    = 0x0104
	wmDpiChanged    = 0x02E0
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1
	wmRunQueue      = wmApp + 2
	wmShutdown      = wmApp + 3
	wmContextMenu   = 0x007B
	ninSelect       = 0x0400
	ninKeySelect    = 0x0401
	ninBalloonClick = 0x0405
	msgfltAllow     = 1
	wsPopup         = 0x80000000
	wsClipChildren  = 0x02000000
	wsOverlappedWin = 0x00CF0000
	wsExTopmost     = 0x00000008
	wsExToolWindow  = 0x00000080
	swHide          = 0
	swShow          = 5
	swShowNA        = 8
	swRestore       = 9
	csRedrawHV      = 0x0003
	idcArrow        = 32512
	colorWindow     = 5
	hwndTopMost     = ^uintptr(0)
	swpNoActivate   = 0x0010
	swpShowWindow   = 0x0040
	swpHideWindow   = 0x0080
	tmeLeave        = 0x00000002
	vkTab           = 0x09
	vkReturn        = 0x0D
	vkShift         = 0x10
	vkEscape        = 0x1B
	vkSpace         = 0x20
	coinitApartment = 0x2
	iccWin95Classes = 0x000000FF
	dpiContextPMV2  = ^uintptr(3)
	monitorDefault  = 2
	smCxSmIcon      = 49
	smMenuDropAlign = 40
	imageIcon       = 1
	lrDefaultSize   = 0x00000040
	lrShared        = 0x00008000
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	shcore   = windows.NewLazySystemDLL("shcore.dll")
	dwmapi   = windows.NewLazySystemDLL("dwmapi.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")
	uxtheme  = windows.NewLazySystemDLL("uxtheme.dll")
	gdiplus  = windows.NewLazySystemDLL("gdiplus.dll")

	procGetModuleHandleW            = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress              = kernel32.NewProc("GetProcAddress")
	procGlobalAlloc                 = kernel32.NewProc("GlobalAlloc")
	procGlobalFree                  = kernel32.NewProc("GlobalFree")
	procRegisterClassExW            = user32.NewProc("RegisterClassExW")
	procCreateWindowExW             = user32.NewProc("CreateWindowExW")
	procDestroyWindow               = user32.NewProc("DestroyWindow")
	procDefWindowProcW              = user32.NewProc("DefWindowProcW")
	procGetMessageW                 = user32.NewProc("GetMessageW")
	procPeekMessageW                = user32.NewProc("PeekMessageW")
	procPostQuitMessage             = user32.NewProc("PostQuitMessage")
	procTranslateMessage            = user32.NewProc("TranslateMessage")
	procDispatchMessageW            = user32.NewProc("DispatchMessageW")
	procPostMessageW                = user32.NewProc("PostMessageW")
	procPostThreadMessageW          = user32.NewProc("PostThreadMessageW")
	procSendMessageW                = user32.NewProc("SendMessageW")
	procRegisterWindowMessageW      = user32.NewProc("RegisterWindowMessageW")
	procChangeWindowMessageFilterEx = user32.NewProc("ChangeWindowMessageFilterEx")
	procShowWindow                  = user32.NewProc("ShowWindow")
	procSetWindowPos                = user32.NewProc("SetWindowPos")
	procGetClientRect               = user32.NewProc("GetClientRect")
	procInvalidateRect              = user32.NewProc("InvalidateRect")
	procBeginPaint                  = user32.NewProc("BeginPaint")
	procEndPaint                    = user32.NewProc("EndPaint")
	procSetForegroundWindow         = user32.NewProc("SetForegroundWindow")
	procGetForegroundWindow         = user32.NewProc("GetForegroundWindow")
	procAllowSetForegroundWindow    = user32.NewProc("AllowSetForegroundWindow")
	procIsIconic                    = user32.NewProc("IsIconic")
	procIsWindowVisible             = user32.NewProc("IsWindowVisible")
	procGetCursorPos                = user32.NewProc("GetCursorPos")
	procMonitorFromPoint            = user32.NewProc("MonitorFromPoint")
	procMonitorFromWindow           = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfoW             = user32.NewProc("GetMonitorInfoW")
	procSetProcessDpiAwarenessCtx   = user32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware          = user32.NewProc("SetProcessDPIAware")
	procGetSystemMetrics            = user32.NewProc("GetSystemMetrics")
	procGetDoubleClickTime          = user32.NewProc("GetDoubleClickTime")
	procLoadCursorW                 = user32.NewProc("LoadCursorW")
	procLoadIconWithScaleDown       = comctl32.NewProc("LoadIconWithScaleDown")
	procTrackMouseEvent             = user32.NewProc("TrackMouseEvent")
	procGetKeyState                 = user32.NewProc("GetKeyState")
	procSetCapture                  = user32.NewProc("SetCapture")
	procReleaseCapture              = user32.NewProc("ReleaseCapture")
	procGetDC                       = user32.NewProc("GetDC")
	procReleaseDC                   = user32.NewProc("ReleaseDC")
	procFillRect                    = user32.NewProc("FillRect")
	procCreateSolidBrush            = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject                = gdi32.NewProc("DeleteObject")
	procCreateDIBSection            = gdi32.NewProc("CreateDIBSection")
	procCreateCompatibleDC          = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC                    = gdi32.NewProc("DeleteDC")
	procSelectObject                = gdi32.NewProc("SelectObject")
	procBitBlt                      = gdi32.NewProc("BitBlt")
	procCreateBitmap                = gdi32.NewProc("CreateBitmap")
	procCreateIconIndirect          = user32.NewProc("CreateIconIndirect")
	procDestroyIcon                 = user32.NewProc("DestroyIcon")
	procCreatePopupMenu             = user32.NewProc("CreatePopupMenu")
	procAppendMenuW                 = user32.NewProc("AppendMenuW")
	procSetMenuDefaultItem          = user32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenuEx            = user32.NewProc("TrackPopupMenuEx")
	procDestroyMenu                 = user32.NewProc("DestroyMenu")
	procShellNotifyIconW            = shell32.NewProc("Shell_NotifyIconW")
	procCoInitializeEx              = ole32.NewProc("CoInitializeEx")
	procCoUninitialize              = ole32.NewProc("CoUninitialize")
	procCoTaskMemFree               = ole32.NewProc("CoTaskMemFree")
	procGetDpiForMonitor            = shcore.NewProc("GetDpiForMonitor")
	procDwmSetWindowAttribute       = dwmapi.NewProc("DwmSetWindowAttribute")
	procInitCommonControlsEx        = comctl32.NewProc("InitCommonControlsEx")
	procGdiplusStartup              = gdiplus.NewProc("GdiplusStartup")
	procGdiplusShutdown             = gdiplus.NewProc("GdiplusShutdown")
)

type winPoint struct {
	X int32
	Y int32
}

type winRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      winPoint
}

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type initCommonControlsEx struct {
	dwSize uint32
	dwICC  uint32
}

type gdiplusStartupInput struct {
	GdiplusVersion           uint32
	DebugEventCallback       uintptr
	SuppressBackgroundThread int32
	SuppressExternalCodecs   int32
}

type monitorInfo struct {
	cbSize    uint32
	rcMonitor winRect
	rcWork    winRect
	dwFlags   uint32
}

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     winRect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

type trackMouseEventStruct struct {
	cbSize      uint32
	dwFlags     uint32
	hwndTrack   uintptr
	dwHoverTime uint32
}

var (
	loopRegistryMu sync.Mutex
	loopByHwnd     = map[uintptr]*Loop{}
	wndProcOnce    sync.Once
	sharedWndProc  uintptr
)

func getWndProc() uintptr {
	wndProcOnce.Do(func() {
		sharedWndProc = windows.NewCallback(dispatchWndProc)
	})
	return sharedWndProc
}

func dispatchWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	loopRegistryMu.Lock()
	l := loopByHwnd[hwnd]
	loopRegistryMu.Unlock()
	if l != nil {
		if handled, res := l.handleMessage(hwnd, msg, wParam, lParam); handled {
			return res
		}
	}
	res, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return res
}

// Loop owns a dedicated STA + PER_MONITOR_AWARE_V2 Win32 UI thread with a
// GDI+ session and hidden top-level message window.
type Loop struct {
	hInstance       uintptr
	trayHwnd        uintptr
	flyoutHwnd      uintptr
	webHwnd         uintptr
	taskbarCreated  uint32
	gdipToken       uintptr
	threadID        uint32
	queueMu         sync.Mutex
	queue           []func()
	closed          bool
	done            chan struct{}
	onTrayMsg       func(wParam, lParam uintptr)
	onTaskbar       func()
	onCommand       func(id uint16)
	onEndSession    func()
	flyoutProc      func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr)
	webProc         func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr)
	classesOnceSync sync.Once
}

var (
	classesOnce sync.Once
	classesErr  error
)

func registerWindowClasses(hInstance uintptr) error {
	classesOnce.Do(func() {
		cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
		bg, _, _ := procCreateSolidBrush.Call(0x00100E0C) // #0C0E10 in COLORREF (0x00BBGGRR)
		proc := getWndProc()
		for _, spec := range []struct {
			name  string
			style uint32
			bg    uintptr
		}{
			{"NetSwitchTrayWindow", 0, 0},
			{"NetSwitchFlyoutWindow", csRedrawHV, 0},
			{"NetSwitchWebViewWindow", csRedrawHV, bg},
		} {
			cname, err := windows.UTF16PtrFromString(spec.name)
			if err != nil {
				classesErr = err
				return
			}
			wc := wndClassExW{
				cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
				style:         spec.style,
				lpfnWndProc:   proc,
				hInstance:     hInstance,
				hCursor:       cursor,
				hbrBackground: spec.bg,
				lpszClassName: cname,
			}
			atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
			runtime.KeepAlive(cname)
			if atom == 0 && callErr != windows.ERROR_CLASS_ALREADY_EXISTS {
				classesErr = fmt.Errorf("RegisterClassExW %s: %w", spec.name, callErr)
				return
			}
		}
	})
	return classesErr
}

// StartLoop spawns the UI thread, initializes DPI awareness, COM STA, GDI+,
// and creates the hidden top-level tray owner window.
func StartLoop(windowTitle string) (*Loop, error) {
	if windowTitle == "" {
		windowTitle = "Net Switch tray"
	}
	l := &Loop{done: make(chan struct{})}
	ready := make(chan error, 1)
	go l.runThread(windowTitle, ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Loop) runThread(windowTitle string, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(l.done)

	l.threadID = windows.GetCurrentThreadId()
	enableDPIAwareness()
	_ = comctl32.Load()
	icc := initCommonControlsEx{dwSize: uint32(unsafe.Sizeof(initCommonControlsEx{})), dwICC: iccWin95Classes}
	_, _, _ = procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	hr, _, _ := procCoInitializeEx.Call(0, coinitApartment)
	if int32(hr) >= 0 {
		defer procCoUninitialize.Call()
	}

	var gdipToken uintptr
	input := gdiplusStartupInput{GdiplusVersion: 1}
	if status, _, _ := procGdiplusStartup.Call(uintptr(unsafe.Pointer(&gdipToken)), uintptr(unsafe.Pointer(&input)), 0); status == 0 {
		l.gdipToken = gdipToken
		defer procGdiplusShutdown.Call(gdipToken)
	}

	hInst, _, _ := procGetModuleHandleW.Call(0)
	l.hInstance = hInst
	if err := registerWindowClasses(hInst); err != nil {
		ready <- err
		return
	}

	classPtr, _ := windows.UTF16PtrFromString("NetSwitchTrayWindow")
	titlePtr, _ := windows.UTF16PtrFromString(windowTitle)
	hwnd, _, callErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		wsPopup,
		0, 0, 0, 0,
		0, // Top-level so TaskbarCreated broadcasts reach it
		0,
		hInst,
		0,
	)
	runtime.KeepAlive(classPtr)
	runtime.KeepAlive(titlePtr)
	if hwnd == 0 {
		ready <- fmt.Errorf("CreateWindowExW tray: %w", callErr)
		return
	}
	l.trayHwnd = hwnd
	l.registerHwnd(hwnd)
	defer func() {
		l.unregisterHwnd(hwnd)
		_, _, _ = procDestroyWindow.Call(hwnd)
	}()

	tbName, _ := windows.UTF16PtrFromString("TaskbarCreated")
	tbMsg, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbName)))
	runtime.KeepAlive(tbName)
	l.taskbarCreated = uint32(tbMsg)
	if l.taskbarCreated != 0 {
		_, _, _ = procChangeWindowMessageFilterEx.Call(hwnd, uintptr(l.taskbarCreated), msgfltAllow, 0)
	}
	tryAllowDarkMenus()

	// Drain any leftover messages if the Go runtime reused a prior OS thread.
	var stale winMsg
	for {
		r, _, _ := procPeekMessageW.Call(uintptr(unsafe.Pointer(&stale)), 0, 0, 0, 1)
		if r == 0 {
			break
		}
	}

	ready <- nil

	var msg winMsg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (l *Loop) registerHwnd(hwnd uintptr) {
	loopRegistryMu.Lock()
	loopByHwnd[hwnd] = l
	loopRegistryMu.Unlock()
}

func (l *Loop) unregisterHwnd(hwnd uintptr) {
	loopRegistryMu.Lock()
	delete(loopByHwnd, hwnd)
	loopRegistryMu.Unlock()
}

func (l *Loop) handleMessage(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr) {
	if hwnd == l.flyoutHwnd && l.flyoutProc != nil {
		if handled, res := l.flyoutProc(hwnd, msg, wParam, lParam); handled {
			return true, res
		}
	}
	if hwnd == l.webHwnd && l.webProc != nil {
		if handled, res := l.webProc(hwnd, msg, wParam, lParam); handled {
			return true, res
		}
	}
	if hwnd != l.trayHwnd {
		return false, 0
	}
	switch {
	case msg == wmRunQueue:
		l.drainQueue()
		return true, 0
	case msg == wmShutdown:
		_, _, _ = procPostQuitMessage.Call(0)
		return true, 0
	case msg == wmTrayCallback:
		if l.onTrayMsg != nil {
			l.onTrayMsg(wParam, lParam)
		}
		return true, 0
	case l.taskbarCreated != 0 && msg == l.taskbarCreated:
		if l.onTaskbar != nil {
			l.onTaskbar()
		}
		return true, 0
	case msg == wmCommand:
		if l.onCommand != nil {
			l.onCommand(uint16(wParam & 0xFFFF))
		}
		return true, 0
	case msg == wmEndSession:
		if wParam != 0 && l.onEndSession != nil {
			l.onEndSession()
		}
		return true, 0
	}
	return false, 0
}

func (l *Loop) drainQueue() {
	for {
		l.queueMu.Lock()
		if len(l.queue) == 0 {
			l.queueMu.Unlock()
			return
		}
		batch := l.queue
		l.queue = nil
		l.queueMu.Unlock()
		for _, fn := range batch {
			fn()
		}
	}
}

// Post enqueues fn to run asynchronously on the UI thread.
func (l *Loop) Post(fn func()) {
	if fn == nil {
		return
	}
	l.queueMu.Lock()
	if l.closed {
		l.queueMu.Unlock()
		return
	}
	l.queue = append(l.queue, fn)
	l.queueMu.Unlock()
	_, _, _ = procPostMessageW.Call(l.trayHwnd, wmRunQueue, 0, 0)
}

// Do runs fn synchronously on the UI thread, or executes directly if already
// on the UI thread.
func (l *Loop) Do(fn func() error) error {
	if fn == nil {
		return nil
	}
	if windows.GetCurrentThreadId() == l.threadID {
		return fn()
	}
	done := make(chan error, 1)
	l.Post(func() {
		done <- fn()
	})
	select {
	case err := <-done:
		return err
	case <-l.done:
		return errors.New("UI loop closed")
	}
}

// Close posts WM_QUIT to the UI thread and waits for teardown.
func (l *Loop) Close() {
	l.queueMu.Lock()
	already := l.closed
	l.closed = true
	l.queue = nil
	l.queueMu.Unlock()
	if already {
		<-l.done
		return
	}
	if l.trayHwnd != 0 {
		_, _, _ = procPostMessageW.Call(l.trayHwnd, wmShutdown, 0, 0)
	}
	<-l.done
}

// Done closes when the UI message loop exits.
func (l *Loop) Done() <-chan struct{} {
	return l.done
}

func enableDPIAwareness() {
	if procSetProcessDpiAwarenessCtx.Find() == nil {
		if r, _, _ := procSetProcessDpiAwarenessCtx.Call(dpiContextPMV2); r != 0 {
			return
		}
	}
	if procSetProcessDPIAware.Find() == nil {
		_, _, _ = procSetProcessDPIAware.Call()
	}
}

func scaleAtPoint(pt winPoint) float64 {
	if procMonitorFromPoint.Find() == nil && procGetDpiForMonitor.Find() == nil {
		ptVal := packPoint(pt)
		mon, _, _ := procMonitorFromPoint.Call(ptVal, monitorDefault)
		if mon != 0 {
			var x, y uint32
			if hr, _, _ := procGetDpiForMonitor.Call(mon, 0, uintptr(unsafe.Pointer(&x)), uintptr(unsafe.Pointer(&y))); hr == 0 && x > 0 {
				return float64(x) / 96.0
			}
		}
	}
	return 1.0
}

func workAreaAtPoint(pt winPoint) winRect {
	mon, _, _ := procMonitorFromPoint.Call(packPoint(pt), monitorDefault)
	if mon != 0 {
		var mi monitorInfo
		mi.cbSize = uint32(unsafe.Sizeof(mi))
		if ok, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); ok != 0 {
			return mi.rcWork
		}
	}
	return winRect{Left: 0, Top: 0, Right: 1920, Bottom: 1080}
}

// packPoint packs a 8-byte POINT {int32 X, int32 Y} into one register for
// by-value Win32 MonitorFromPoint on both x64 and ARM64.
func packPoint(pt winPoint) uintptr {
	return uintptr(uint32(pt.X)) | (uintptr(uint32(pt.Y)) << 32)
}

func tryAllowDarkMenus() {
	// Undocumented uxtheme ordinals (Windows 10 1903+): SetPreferredAppMode(135), FlushMenuThemes(136).
	if uxtheme.Load() != nil {
		return
	}
	h := uintptr(uxtheme.Handle())
	setAppMode, _, _ := procGetProcAddress.Call(h, 135)
	flushMenuThemes, _, _ := procGetProcAddress.Call(h, 136)
	if setAppMode != 0 {
		_, _, _ = syscall.SyscallN(setAppMode, 1) // PreferredAppMode::AllowDark
	}
	if flushMenuThemes != 0 {
		_, _, _ = syscall.SyscallN(flushMenuThemes)
	}
}

func flyoutDwmStyle(hwnd uintptr, edgeRGB uint32) bool {
	if dwmapi.Load() != nil {
		return false
	}
	dark := int32(1)
	corners := int32(2) // DWMWCP_ROUND
	backdrop := int32(3)
	border := int32(edgeRGB)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&dark)), 4)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 38, uintptr(unsafe.Pointer(&backdrop)), 4)
	hr1, _, _ := procDwmSetWindowAttribute.Call(hwnd, 33, uintptr(unsafe.Pointer(&corners)), 4)
	hr2, _, _ := procDwmSetWindowAttribute.Call(hwnd, 34, uintptr(unsafe.Pointer(&border)), 4)
	return hr1 == 0 && hr2 == 0
}

func darkWindowFrame(hwnd uintptr) {
	if dwmapi.Load() != nil {
		return
	}
	dark := int32(1)
	caption := int32(0x00100E0C) // #0C0E10 in COLORREF (0x00BBGGRR)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&dark)), 4)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, 35, uintptr(unsafe.Pointer(&caption)), 4)
}
