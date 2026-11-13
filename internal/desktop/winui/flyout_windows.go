//go:build windows

package winui

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/AyoubAchour/net-switch/internal/desktop"
)

const (
	flyoutWidthDip         = 372
	flyoutPad              = 16
	flyoutGap              = 14
	flyoutInner            = flyoutWidthDip - 2*flyoutPad // 340
	flyoutHeaderHeight     = 35
	flyoutTilesTop         = flyoutPad + flyoutHeaderHeight + flyoutGap // 65
	flyoutTileWidth        = (flyoutInner - 8) / 2                      // 166
	flyoutTileHeight       = 82
	flyoutLinesTop         = flyoutTilesTop + flyoutTileHeight + flyoutGap // 161
	flyoutLineGap          = 10
	flyoutMoreHeight       = 16
	flyoutAppsHeadHeight   = 18
	flyoutRowHeight        = 39
	flyoutRowGap           = 2
	flyoutUnavailableH     = 84
	flyoutMinNameRoom      = 96
	flyoutMaxControl2      = 196
	flyoutMaxControl3      = 216
	flyoutMaxChosen        = 110
	flyoutFooterTextLeft   = flyoutPad + 13 + 6
	flyoutFooterTextWidth  = 280
	gpPixelFormat32bppARGB = 0x0026200A
	gpTextRenderClearType  = 5
	gpAlignNear            = 0
	gpAlignCenter          = 1
	gpAlignFar             = 2
	gpTrimEllipsisChar     = 3
	gpFormatFlagNoWrap     = 0x00001000
	gpFormatFlagLineLimit  = 0x00002000

	ttmActivate        = 0x0401
	ttmSetMaxTipWidth  = 0x0418
	ttmAddToolW        = 0x0432
	ttmUpdateTipTextW  = 0x0439
	ttfIDIsHwnd        = 0x0001
	ttfSubclass        = 0x0010
	ttsAlwaysTip       = 0x01
	ttsNoPrefix        = 0x02
	swpNoSize          = 0x0001
	swpNoMove          = 0x0002
	swpNoActivateFlag  = 0x0010
	srccopy            = 0x00CC0020
	hwndMessageNoClose = 0
)

var (
	colBg           = color.NRGBA{R: 32, G: 32, B: 32, A: 255}
	colCard         = color.NRGBA{R: 43, G: 43, B: 43, A: 255}
	colStroke       = color.NRGBA{R: 58, G: 58, B: 58, A: 255}
	colHairline     = color.NRGBA{R: 74, G: 74, B: 74, A: 255}
	colEdge         = color.NRGBA{R: 54, G: 54, B: 54, A: 255}
	colFooterFill   = color.NRGBA{R: 26, G: 26, B: 26, A: 255}
	colSegmentFill  = color.NRGBA{R: 28, G: 28, B: 28, A: 255}
	colSelectedFill = color.NRGBA{R: 50, G: 50, B: 50, A: 255}
	colUnlit        = color.NRGBA{R: 68, G: 68, B: 68, A: 255}
	colUnlitDown    = color.NRGBA{R: 52, G: 52, B: 52, A: 255}
	colSecondary    = color.NRGBA{R: 197, G: 197, B: 197, A: 255}
	colDim          = color.NRGBA{R: 142, G: 142, B: 142, A: 255}
	colFaint        = color.NRGBA{R: 96, G: 96, B: 96, A: 255}
	colAccent       = color.NRGBA{R: 76, G: 194, B: 255, A: 255}
	colInk          = color.NRGBA{R: 0, G: 42, B: 61, A: 255}
	colInkSoft      = color.NRGBA{R: 0, G: 64, B: 92, A: 255}
	colAvatarInk    = color.NRGBA{R: 17, G: 17, B: 17, A: 255}
	colGreen        = color.NRGBA{R: 108, G: 203, B: 95, A: 255}
	colWarning      = color.NRGBA{R: 242, G: 178, B: 77, A: 255}
	colRed          = color.NRGBA{R: 242, G: 109, B: 109, A: 255}
	colWhite        = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	colTransparent  = color.NRGBA{}

	flyoutPalette = []color.NRGBA{
		{R: 245, G: 177, B: 61, A: 255},
		{R: 60, G: 200, B: 234, A: 255},
		{R: 179, G: 148, B: 255, A: 255},
		{R: 245, G: 132, B: 200, A: 255},
		{R: 185, G: 220, B: 88, A: 255},
		{R: 127, G: 153, B: 255, A: 255},
	}
	flyoutAvatars = []color.NRGBA{
		{R: 61, G: 220, B: 132, A: 255},
		{R: 154, G: 164, B: 178, A: 255},
		{R: 255, G: 113, B: 57, A: 255},
		colAccent,
		flyoutPalette[0],
		{R: 199, G: 161, B: 245, A: 255},
	}
)

var (
	procGdipCreateBitmapFromScan0              = gdiplus.NewProc("GdipCreateBitmapFromScan0")
	procGdipDisposeImage                       = gdiplus.NewProc("GdipDisposeImage")
	procGdipGetImageGraphicsContext            = gdiplus.NewProc("GdipGetImageGraphicsContext")
	procGdipDeleteGraphics                     = gdiplus.NewProc("GdipDeleteGraphics")
	procGdipSetTextRenderingHint               = gdiplus.NewProc("GdipSetTextRenderingHint")
	procGdipCreateFontFromLogfontW             = gdiplus.NewProc("GdipCreateFontFromLogfontW")
	procGdipDeleteFont                         = gdiplus.NewProc("GdipDeleteFont")
	procGdipGetFamily                          = gdiplus.NewProc("GdipGetFamily")
	procGdipGetFamilyName                      = gdiplus.NewProc("GdipGetFamilyName")
	procGdipDeleteFontFamily                   = gdiplus.NewProc("GdipDeleteFontFamily")
	procGdipGetFontHeight                      = gdiplus.NewProc("GdipGetFontHeight")
	procGdipCreateSolidFill                    = gdiplus.NewProc("GdipCreateSolidFill")
	procGdipDeleteBrush                        = gdiplus.NewProc("GdipDeleteBrush")
	procGdipCreateStringFormat                 = gdiplus.NewProc("GdipCreateStringFormat")
	procGdipDeleteStringFormat                 = gdiplus.NewProc("GdipDeleteStringFormat")
	procGdipSetStringFormatAlign               = gdiplus.NewProc("GdipSetStringFormatAlign")
	procGdipSetStringFormatLineAlign           = gdiplus.NewProc("GdipSetStringFormatLineAlign")
	procGdipSetStringFormatTrimming            = gdiplus.NewProc("GdipSetStringFormatTrimming")
	procGdipSetStringFormatFlags               = gdiplus.NewProc("GdipSetStringFormatFlags")
	procGdipSetStringFormatMeasurableCharRange = gdiplus.NewProc("GdipSetStringFormatMeasurableCharacterRanges")
	procGdipCreateRegion                       = gdiplus.NewProc("GdipCreateRegion")
	procGdipDeleteRegion                       = gdiplus.NewProc("GdipDeleteRegion")
	procGdipMeasureCharacterRanges             = gdiplus.NewProc("GdipMeasureCharacterRanges")
	procGdipGetRegionBounds                    = gdiplus.NewProc("GdipGetRegionBounds")
	procGdipMeasureString                      = gdiplus.NewProc("GdipMeasureString")
	procGdipDrawString                         = gdiplus.NewProc("GdipDrawString")
)

type logfontW struct {
	lfHeight         int32
	lfWidth          int32
	lfEscapement     int32
	lfOrientation    int32
	lfWeight         int32
	lfItalic         byte
	lfUnderline      byte
	lfStrikeOut      byte
	lfCharSet        byte
	lfOutPrecision   byte
	lfClipPrecision  byte
	lfQuality        byte
	lfPitchAndFamily byte
	lfFaceName       [32]uint16
}

type rectF struct {
	X      float32
	Y      float32
	Width  float32
	Height float32
}

type characterRange struct {
	First  int32
	Length int32
}

type toolInfoW struct {
	cbSize     uint32
	uFlags     uint32
	hwnd       uintptr
	uId        uintptr
	rect       winRect
	hinst      uintptr
	lpszText   *uint16
	lParam     uintptr
	lpReserved uintptr
}

type flyoutFontSpec struct {
	preferred string
	fallback  string
	px        float64
	weight    int32
	fallbackW int32
}

type flyoutFonts struct {
	title       uintptr
	label       uintptr
	strong      uintptr
	body        uintptr
	smallStrong uintptr
	small       uintptr
	badge       uintptr
	letter      uintptr
	mono        uintptr
	monoSmall   uintptr

	titlePx       float64
	labelPx       float64
	strongPx      float64
	bodyPx        float64
	smallStrongPx float64
	smallPx       float64
	badgePx       float64
	letterPx      float64
	monoPx        float64
	monoSmallPx   float64
	smallHeight   float64
}

type flyoutRectF struct {
	x, y, w, h float32
}

func (r flyoutRectF) contains(x, y float32) bool {
	return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h
}

// FlyoutAction identifies an interactive element in the flyout.
type FlyoutAction struct {
	Key      string
	Endpoint string
	Body     map[string]any
}

type flyoutHit struct {
	bounds flyoutRectF
	action FlyoutAction
	tip    string
}

type flyoutNote struct {
	bounds flyoutRectF
	tip    string
}

// FlyoutWindow owns the Win32 DWM popup flyout for Net Switch.
type FlyoutWindow struct {
	loop      *Loop
	hwnd      uintptr
	tipHwnd   uintptr
	onAction  func(FlyoutAction)
	view      desktop.FlyoutView
	scale     float64
	edgeDWM   bool
	workArea  winRect
	hits      []flyoutHit
	notes     []flyoutNote
	hover     string
	keyboard  string
	pressed   string
	pending   string
	errMsg    string
	quitting  bool
	tip       string
	visible   bool
	tracking  bool
	dismissAt time.Time
	dismissX  int32
	dismissY  int32
	closed    bool
}

// NewFlyoutWindow creates the hidden borderless flyout popup on loop's UI thread.
func NewFlyoutWindow(loop *Loop, onAction func(FlyoutAction)) (*FlyoutWindow, error) {
	if loop == nil {
		return nil, fmt.Errorf("flyout requires an active Loop")
	}
	f := &FlyoutWindow{
		loop:     loop,
		onAction: onAction,
		view:     desktop.UnavailableFlyout("Connecting to Net Switch\u2026"),
		scale:    1.0,
	}
	err := loop.Do(func() error {
		loop.flyoutProc = f.handleMessage
		cname, err := windows.UTF16PtrFromString("NetSwitchFlyoutWindow")
		if err != nil {
			return err
		}
		tname, err := windows.UTF16PtrFromString("Net Switch flyout")
		if err != nil {
			return err
		}
		hwnd, _, callErr := procCreateWindowExW.Call(
			wsExTopmost|wsExToolWindow,
			uintptr(unsafe.Pointer(cname)),
			uintptr(unsafe.Pointer(tname)),
			wsPopup,
			0, 0, flyoutWidthDip, 320,
			0, 0, loop.hInstance, 0,
		)
		runtime.KeepAlive(cname)
		runtime.KeepAlive(tname)
		if hwnd == 0 {
			return fmt.Errorf("CreateWindowExW flyout: %w", callErr)
		}
		f.hwnd = hwnd
		loop.flyoutHwnd = hwnd
		loop.registerHwnd(hwnd)
		f.edgeDWM = flyoutDwmStyle(hwnd, 0x00363636)
		f.createTooltip()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (f *FlyoutWindow) createTooltip() {
	tc, _ := windows.UTF16PtrFromString("tooltips_class32")
	tt, _, _ := procCreateWindowExW.Call(
		wsExTopmost,
		uintptr(unsafe.Pointer(tc)),
		0,
		wsPopup|ttsAlwaysTip|ttsNoPrefix,
		0, 0, 0, 0,
		f.hwnd, 0, f.loop.hInstance, 0,
	)
	runtime.KeepAlive(tc)
	if tt == 0 {
		return
	}
	f.tipHwnd = tt
	_, _, _ = procSendMessageW.Call(tt, ttmSetMaxTipWidth, 0, 420)
	empty := []uint16{0}
	ti := toolInfoW{
		cbSize:   uint32(unsafe.Sizeof(toolInfoW{})),
		uFlags:   ttfIDIsHwnd | ttfSubclass,
		hwnd:     f.hwnd,
		uId:      f.hwnd,
		lpszText: &empty[0],
	}
	_, _, _ = procSendMessageW.Call(tt, ttmAddToolW, 0, uintptr(unsafe.Pointer(&ti)))
	runtime.KeepAlive(empty)
}

func (f *FlyoutWindow) setTooltipText(text string) {
	if f.tipHwnd == 0 || f.tip == text {
		return
	}
	f.tip = text
	if text == "" {
		_, _, _ = procSendMessageW.Call(f.tipHwnd, ttmActivate, 0, 0)
		return
	}
	u := utf16.Encode([]rune(strings.ReplaceAll(text, "\x00", "")))
	u = append(u, 0)
	ti := toolInfoW{
		cbSize:   uint32(unsafe.Sizeof(toolInfoW{})),
		uFlags:   ttfIDIsHwnd | ttfSubclass,
		hwnd:     f.hwnd,
		uId:      f.hwnd,
		lpszText: &u[0],
	}
	_, _, _ = procSendMessageW.Call(f.tipHwnd, ttmUpdateTipTextW, 0, uintptr(unsafe.Pointer(&ti)))
	runtime.KeepAlive(u)
	_, _, _ = procSendMessageW.Call(f.tipHwnd, ttmActivate, 1, 0)
}

// SetView updates the rendered FlyoutView and repaints if visible.
func (f *FlyoutWindow) SetView(next desktop.FlyoutView) {
	if f == nil || f.loop == nil {
		return
	}
	f.loop.Post(func() {
		if f.closed {
			return
		}
		f.view = next
		if f.visible {
			f.place()
			_, _, _ = procInvalidateRect.Call(f.hwnd, 0, 0)
		}
	})
}

// SetFeedback updates transient pending/error/quitting footer state.
func (f *FlyoutWindow) SetFeedback(action, message string, quitting bool) {
	if f == nil || f.loop == nil {
		return
	}
	f.loop.Post(func() {
		if f.closed {
			return
		}
		f.pending = action
		f.errMsg = message
		f.quitting = quitting
		if f.visible {
			f.place()
			_, _, _ = procInvalidateRect.Call(f.hwnd, 0, 0)
		}
	})
}

// ToggleAt toggles visibility near anchor (or hides if already visible).
func (f *FlyoutWindow) ToggleAt(anchorX, anchorY int32) {
	if f == nil || f.loop == nil {
		return
	}
	f.loop.Post(func() {
		if f.closed || f.hwnd == 0 {
			return
		}
		if f.visible {
			_, _, _ = procShowWindow.Call(f.hwnd, swHide)
			f.visible = false
			return
		}
		pt := winPoint{X: anchorX, Y: anchorY}
		if pt.X == 0 && pt.Y == 0 {
			_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
		}
		f.workArea = workAreaAtPoint(pt)
		f.scale = scaleAtPoint(pt)
		f.hover, f.keyboard, f.pressed = "", "", ""
		f.place()
		_, _, _ = procShowWindow.Call(f.hwnd, swShow)
		_, _, _ = procSetForegroundWindow.Call(f.hwnd)
		f.visible = true
		_, _, _ = procInvalidateRect.Call(f.hwnd, 0, 0)
	})
}

// DismissInfo returns when and where the flyout was last deactivated so a
// tray click used to dismiss it does not immediately reopen it.
func (f *FlyoutWindow) DismissInfo() (time.Time, int32, int32) {
	if f == nil {
		return time.Time{}, 0, 0
	}
	var at time.Time
	var x, y int32
	_ = f.loop.Do(func() error {
		at, x, y = f.dismissAt, f.dismissX, f.dismissY
		return nil
	})
	return at, x, y
}

// Close destroys the flyout window and tooltip child.
func (f *FlyoutWindow) Close() {
	if f == nil || f.loop == nil {
		return
	}
	_ = f.loop.Do(func() error {
		if f.closed {
			return nil
		}
		f.closed = true
		if f.tipHwnd != 0 {
			_, _, _ = procDestroyWindow.Call(f.tipHwnd)
			f.tipHwnd = 0
		}
		if f.hwnd != 0 {
			f.loop.flyoutProc = nil
			f.loop.flyoutHwnd = 0
			f.loop.unregisterHwnd(f.hwnd)
			_, _, _ = procDestroyWindow.Call(f.hwnd)
			f.hwnd = 0
		}
		return nil
	})
}

func (f *FlyoutWindow) place() {
	if f.hwnd == 0 {
		return
	}
	w, h, _ := f.measureDimensions(0)
	margin := int32(math.Round(12 * f.scale))
	x := f.workArea.Right - int32(w) - margin
	y := f.workArea.Bottom - int32(h) - margin
	if x < f.workArea.Left+margin {
		x = f.workArea.Left + margin
	}
	if y < f.workArea.Top+margin {
		y = f.workArea.Top + margin
	}
	_, _, _ = procSetWindowPos.Call(f.hwnd, hwndTopMost, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpNoActivateFlag)
}

func (f *FlyoutWindow) measureDimensions(hdc uintptr) (int, int, float64) {
	renderer := newFlyoutRenderer(f.view, f.scale, f.hover, f.keyboard, f.pressed, f.pending, f.errMsg, f.quitting, !f.edgeDWM, hdc)
	defer renderer.close()
	totalLogical := float64(renderer.contentBottom()) + float64(renderer.footerHeight())
	w := int(math.Round(float64(flyoutWidthDip) * f.scale))
	h := int(math.Round(totalLogical * f.scale))
	return w, h, totalLogical
}

func (f *FlyoutWindow) handleMessage(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr) {
	switch msg {
	case wmEraseBkgnd:
		return true, 1
	case wmActivate:
		if uint16(wParam&0xFFFF) == 0 {
			f.dismissAt = time.Now()
			var pt winPoint
			_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
			f.dismissX, f.dismissY = pt.X, pt.Y
			f.visible = false
			_, _, _ = procShowWindow.Call(hwnd, swHide)
		}
		return true, 0
	case wmDpiChanged:
		dpi := float64(uint16(wParam & 0xFFFF))
		if dpi > 0 {
			f.scale = dpi / 96.0
		}
		mon, _, _ := procMonitorFromWindow.Call(hwnd, monitorDefault)
		if mon != 0 {
			var mi monitorInfo
			mi.cbSize = uint32(unsafe.Sizeof(mi))
			if ok, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); ok != 0 {
				f.workArea = mi.rcWork
			}
		}
		f.place()
		_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		return true, 0
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			f.paint(hdc)
			_, _, _ = procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return true, 0
	case wmMouseMove:
		if !f.tracking {
			tme := trackMouseEventStruct{
				cbSize:    uint32(unsafe.Sizeof(trackMouseEventStruct{})),
				dwFlags:   tmeLeave,
				hwndTrack: hwnd,
			}
			_, _, _ = procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&tme)))
			f.tracking = true
		}
		lx := float32(int16(lParam&0xFFFF)) / float32(f.scale)
		ly := float32(int16((lParam>>16)&0xFFFF)) / float32(f.scale)
		hit := f.hitAt(lx, ly)
		nextHover := ""
		if hit != nil {
			nextHover = hit.action.Key
		}
		nextTip := ""
		if hit != nil {
			nextTip = hit.tip
		} else if note := f.noteAt(lx, ly); note != nil {
			nextTip = note.tip
		} else if ly >= float32(flyoutContentBottom(f.view)) {
			nextTip = flyoutFooterMessage(f.view, f.errMsg, f.quitting)
		}
		f.setTooltipText(nextTip)
		if nextHover != f.hover {
			f.hover = nextHover
			_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		}
		return true, 0
	case wmMouseLeave:
		f.tracking = false
		if f.hover != "" {
			f.hover = ""
			_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		}
		return true, 0
	case wmLButtonDown:
		lx := float32(int16(lParam&0xFFFF)) / float32(f.scale)
		ly := float32(int16((lParam>>16)&0xFFFF)) / float32(f.scale)
		hit := f.hitAt(lx, ly)
		f.pressed = ""
		if hit != nil {
			f.pressed = hit.action.Key
		}
		f.keyboard = ""
		_, _, _ = procSetCapture.Call(hwnd)
		_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		return true, 0
	case wmLButtonUp:
		_, _, _ = procReleaseCapture.Call()
		lx := float32(int16(lParam&0xFFFF)) / float32(f.scale)
		ly := float32(int16((lParam>>16)&0xFFFF)) / float32(f.scale)
		hit := f.hitAt(lx, ly)
		before := f.pressed
		f.pressed = ""
		_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		if hit != nil && hit.action.Key == before && f.onAction != nil {
			f.onAction(hit.action)
		}
		return true, 0
	case wmKeyDown, wmSysKeyDown:
		switch uint32(wParam) {
		case vkEscape:
			f.visible = false
			_, _, _ = procShowWindow.Call(hwnd, swHide)
			return true, 0
		case vkTab:
			if len(f.hits) > 0 {
				idx := -1
				for i, h := range f.hits {
					if h.action.Key == f.keyboard {
						idx = i
						break
					}
				}
				step := 1
				if ks, _, _ := procGetKeyState.Call(vkShift); ks&0x8000 != 0 {
					step = -1
				}
				f.keyboard = f.hits[(idx+step+len(f.hits))%len(f.hits)].action.Key
				_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
			}
			return true, 0
		case vkReturn, vkSpace:
			for _, h := range f.hits {
				if h.action.Key == f.keyboard && f.onAction != nil {
					f.onAction(h.action)
					break
				}
			}
			return true, 0
		}
	}
	return false, 0
}

func (f *FlyoutWindow) hitAt(x, y float32) *flyoutHit {
	for i := range f.hits {
		if f.hits[i].bounds.contains(x, y) {
			return &f.hits[i]
		}
	}
	return nil
}

func (f *FlyoutWindow) noteAt(x, y float32) *flyoutNote {
	for i := range f.notes {
		if f.notes[i].bounds.contains(x, y) {
			return &f.notes[i]
		}
	}
	return nil
}

func (f *FlyoutWindow) paint(hdc uintptr) {
	r := newFlyoutRenderer(f.view, f.scale, f.hover, f.keyboard, f.pressed, f.pending, f.errMsg, f.quitting, !f.edgeDWM, hdc)
	defer r.close()
	hBmp, w, h, err := r.renderToDIB()
	if err != nil {
		return
	}
	defer func() { _, _, _ = procDeleteObject.Call(hBmp) }()
	f.hits = r.hits
	f.notes = r.notes

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return
	}
	defer func() { _, _, _ = procDeleteDC.Call(memDC) }()
	oldBmp, _, _ := procSelectObject.Call(memDC, hBmp)
	_, _, _ = procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), memDC, 0, 0, srccopy)
	_, _, _ = procSelectObject.Call(memDC, oldBmp)
}

// SnapshotPNG renders view at scale into an encoded PNG matching FlyoutForm.Snapshot.
func SnapshotPNG(view desktop.FlyoutView, scale float64) ([]byte, error) {
	return SnapshotPNGWithFeedback(view, scale, "", "", false)
}

// SnapshotPNGWithFeedback renders view at scale with optional pending/error/quitting footer state.
func SnapshotPNGWithFeedback(view desktop.FlyoutView, scale float64, pending, errMsg string, quitting bool) ([]byte, error) {
	if scale <= 0 {
		scale = 1.0
	}
	_ = gdiplus.Load()
	var gdipToken uintptr
	input := gdiplusStartupInput{GdiplusVersion: 1}
	status, _, _ := procGdiplusStartup.Call(uintptr(unsafe.Pointer(&gdipToken)), uintptr(unsafe.Pointer(&input)), 0)
	if status != 0 {
		return nil, fmt.Errorf("GdiplusStartup failed: status %d", status)
	}
	defer func() { _, _, _ = procGdiplusShutdown.Call(gdipToken) }()

	r := newFlyoutRenderer(view, scale, "", "", "", pending, errMsg, quitting, true, 0)
	defer r.close()
	hBmp, w, h, err := r.renderToDIB()
	if err != nil {
		return nil, err
	}
	defer func() { _, _, _ = procDeleteObject.Call(hBmp) }()

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	bgra := r.bgra
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := (y*w + x) * 4
			img.Pix[off+0] = bgra[off+2] // R
			img.Pix[off+1] = bgra[off+1] // G
			img.Pix[off+2] = bgra[off+0] // B
			img.Pix[off+3] = bgra[off+3] // A
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type flyoutRenderer struct {
	view     desktop.FlyoutView
	scale    float64
	hover    string
	keyboard string
	pressed  string
	pending  string
	errMsg   string
	quitting bool
	drawEdge bool
	hdc      uintptr
	ownDC    bool
	fonts    flyoutFonts
	gpImg    uintptr
	gpG      uintptr
	hBmp     uintptr
	bgra     []byte
	widthPx  int
	heightPx int
	hits     []flyoutHit
	notes    []flyoutNote
	strFmt   map[uint32]uintptr
}

func newFlyoutRenderer(view desktop.FlyoutView, scale float64, hover, keyboard, pressed, pending, errMsg string, quitting, drawEdge bool, hdc uintptr) *flyoutRenderer {
	if scale <= 0 {
		scale = 1.0
	}
	ownDC := false
	if hdc == 0 {
		hdc, _, _ = procGetDC.Call(0)
		ownDC = hdc != 0
	}
	r := &flyoutRenderer{
		view:     view,
		scale:    scale,
		hover:    hover,
		keyboard: keyboard,
		pressed:  pressed,
		pending:  pending,
		errMsg:   errMsg,
		quitting: quitting,
		drawEdge: drawEdge,
		hdc:      hdc,
		ownDC:    ownDC,
		strFmt:   map[uint32]uintptr{},
	}
	r.fonts = loadFlyoutFonts(hdc, scale)
	return r
}

func (r *flyoutRenderer) close() {
	for _, h := range r.strFmt {
		_, _, _ = procGdipDeleteStringFormat.Call(h)
	}
	r.fonts.dispose()
	if r.gpG != 0 {
		_, _, _ = procGdipDeleteGraphics.Call(r.gpG)
		r.gpG = 0
	}
	if r.gpImg != 0 {
		_, _, _ = procGdipDisposeImage.Call(r.gpImg)
		r.gpImg = 0
	}
	if r.ownDC && r.hdc != 0 {
		_, _, _ = procReleaseDC.Call(0, r.hdc)
		r.hdc = 0
	}
}

func loadFlyoutFonts(hdc uintptr, scale float64) flyoutFonts {
	var f flyoutFonts
	f.title, f.titlePx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text Semibold", "Segoe UI Semibold", 14, 600, 600}, scale)
	f.label, f.labelPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text Semibold", "Segoe UI Semibold", 13, 600, 600}, scale)
	f.strong, f.strongPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text Semibold", "Segoe UI Semibold", 12, 600, 600}, scale)
	f.body, f.bodyPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text", "Segoe UI", 12, 400, 400}, scale)
	f.smallStrong, f.smallStrongPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text Semibold", "Segoe UI Semibold", 11, 600, 600}, scale)
	f.small, f.smallPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text", "Segoe UI", 11, 400, 400}, scale)
	f.badge, f.badgePx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text Semibold", "Segoe UI Semibold", 9, 600, 600}, scale)
	f.letter, f.letterPx = makeGdipFont(hdc, flyoutFontSpec{"Segoe UI Variable Text", "Segoe UI", 11, 700, 700}, scale)
	f.mono, f.monoPx = makeGdipFont(hdc, flyoutFontSpec{"Cascadia Mono", "Consolas", 12, 400, 400}, scale)
	f.monoSmall, f.monoSmallPx = makeGdipFont(hdc, flyoutFontSpec{"Cascadia Mono", "Consolas", 11, 400, 400}, scale)
	f.smallHeight = f.smallPx * 1.33 // refined below once Gdip graphics exists
	return f
}

func (f *flyoutFonts) dispose() {
	for _, ptr := range []uintptr{f.title, f.label, f.strong, f.body, f.smallStrong, f.small, f.badge, f.letter, f.mono, f.monoSmall} {
		if ptr != 0 {
			_, _, _ = procGdipDeleteFont.Call(ptr)
		}
	}
}

func makeGdipFont(hdc uintptr, spec flyoutFontSpec, scale float64) (uintptr, float64) {
	px := spec.px * scale
	create := func(face string, weight int32) uintptr {
		var lf logfontW
		lf.lfHeight = -int32(math.Round(px))
		if lf.lfHeight == 0 {
			lf.lfHeight = -1
		}
		lf.lfWeight = weight
		lf.lfQuality = 5 // CLEARTYPE_QUALITY
		u := utf16.Encode([]rune(face))
		if len(u) > len(lf.lfFaceName)-1 {
			u = u[:len(lf.lfFaceName)-1]
		}
		copy(lf.lfFaceName[:], u)
		var font uintptr
		status, _, _ := procGdipCreateFontFromLogfontW.Call(hdc, uintptr(unsafe.Pointer(&lf)), uintptr(unsafe.Pointer(&font)))
		if status != 0 {
			return 0
		}
		return font
	}
	font := create(spec.preferred, spec.weight)
	if font != 0 && !fontMatchesFamily(font, spec.preferred) {
		_, _, _ = procGdipDeleteFont.Call(font)
		font = create(spec.fallback, spec.fallbackW)
	}
	if font == 0 {
		font = create(spec.fallback, spec.fallbackW)
	}
	return font, spec.px
}

func fontMatchesFamily(font uintptr, want string) bool {
	var fam uintptr
	if status, _, _ := procGdipGetFamily.Call(font, uintptr(unsafe.Pointer(&fam))); status != 0 || fam == 0 {
		return false
	}
	defer func() { _, _, _ = procGdipDeleteFontFamily.Call(fam) }()
	var buf [32]uint16
	if status, _, _ := procGdipGetFamilyName.Call(fam, uintptr(unsafe.Pointer(&buf[0])), 0); status != 0 {
		return false
	}
	got := windows.UTF16ToString(buf[:])
	// Windows reports "Segoe UI Variable Text" as the family name even for its
	// "Segoe UI Variable Text Semibold" substyle.
	return strings.EqualFold(got, want) || (strings.HasPrefix(strings.ToLower(want), strings.ToLower(got)) && len(got) >= 6)
}

func (r *flyoutRenderer) contentBottom() int {
	return flyoutContentBottom(r.view)
}

func flyoutContentBottom(view desktop.FlyoutView) int {
	if !view.Available {
		return flyoutTilesTop + flyoutUnavailableH + flyoutPad
	}
	rows := len(view.Apps)
	if rows < 1 {
		rows = 1
	}
	return flyoutRowsTop(view) + rows*flyoutRowHeight + (rows-1)*flyoutRowGap + flyoutPad
}

func flyoutLineRowHeight(line desktop.FlyoutLine) int {
	if line.Note != "" {
		return 23 + 14
	}
	return 23 + 6
}

func flyoutLinesHeight(view desktop.FlyoutView) int {
	h := 12
	if len(view.Lines) == 0 {
		h += 16
	}
	for i, line := range view.Lines {
		if i > 0 {
			h += flyoutLineGap
		}
		h += flyoutLineRowHeight(line)
	}
	if view.MoreLines > 0 {
		h += flyoutLineGap + flyoutMoreHeight
	}
	return h + 12
}

func flyoutAppsTop(view desktop.FlyoutView) int {
	return flyoutLinesTop + flyoutLinesHeight(view) + flyoutGap
}

func flyoutRowsTop(view desktop.FlyoutView) int {
	return flyoutAppsTop(view) + flyoutAppsHeadHeight + flyoutGap
}

func flyoutFooterMessage(view desktop.FlyoutView, errMsg string, quitting bool) string {
	if quitting {
		return "Net Switch is quitting\u2026"
	}
	if errMsg != "" {
		return errMsg
	}
	if view.Available {
		return view.Health
	}
	return "Open Net Switch to reconnect"
}

func (r *flyoutRenderer) smallLineHeight() float64 {
	if r.gpG != 0 && r.fonts.small != 0 {
		var h float32
		if st, _, _ := procGdipGetFontHeight.Call(r.fonts.small, r.gpG, uintptr(unsafe.Pointer(&h))); st == 0 && h > 0 {
			return float64(h) / r.scale
		}
	}
	return r.fonts.smallHeight
}

func (r *flyoutRenderer) footerLines() int {
	line := r.smallLineHeight()
	if r.gpG == 0 || r.fonts.small == 0 {
		msg := flyoutFooterMessage(r.view, r.errMsg, r.quitting)
		if len(msg) > 48 {
			return 2
		}
		return 1
	}
	pad := r.fonts.smallPx / 6.0
	room := rectF{
		X:      0,
		Y:      0,
		Width:  float32((flyoutFooterTextWidth + 2*pad) * r.scale),
		Height: float32((3*line + 1) * r.scale),
	}
	fmtHandle := r.getStringFormat(gpAlignNear, true)
	msg := flyoutFooterMessage(r.view, r.errMsg, r.quitting)
	if msg == "" {
		return 1
	}
	u := utf16.Encode([]rune(msg))
	var box rectF
	_, _, _ = procGdipMeasureString.Call(
		r.gpG,
		uintptr(unsafe.Pointer(&u[0])),
		uintptr(len(u)),
		r.fonts.small,
		uintptr(unsafe.Pointer(&room)),
		fmtHandle,
		uintptr(unsafe.Pointer(&box)),
		0, 0,
	)
	runtime.KeepAlive(u)
	measured := float64(box.Height) / r.scale
	n := int(math.Round(measured / line))
	if n < 1 {
		return 1
	}
	if n > 3 {
		return 3
	}
	return n
}

func (r *flyoutRenderer) footerHeight() int {
	lines := r.footerLines()
	if lines == 1 {
		return 33
	}
	return 20 + int(math.Ceil(float64(lines)*r.smallLineHeight()))
}

func (r *flyoutRenderer) renderToDIB() (uintptr, int, int, error) {
	// Create a tiny 1x1 graphics context first so MeasureString in footerLines
	// matches ClearType font line height before sizing the final DIB.
	var probeBits unsafe.Pointer
	probeBMI := bitmapInfoHeader{
		biSize: uint32(unsafe.Sizeof(bitmapInfoHeader{})), biWidth: 1, biHeight: -1, biPlanes: 1, biBitCount: 32,
	}
	probeBmp, _, err := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&probeBMI)), 0, uintptr(unsafe.Pointer(&probeBits)), 0, 0)
	if probeBmp != 0 && probeBits != nil {
		var pImg, pG uintptr
		if st, _, _ := procGdipCreateBitmapFromScan0.Call(1, 1, 4, gpPixelFormat32bppARGB, uintptr(probeBits), uintptr(unsafe.Pointer(&pImg))); st == 0 && pImg != 0 {
			if st2, _, _ := procGdipGetImageGraphicsContext.Call(pImg, uintptr(unsafe.Pointer(&pG))); st2 == 0 && pG != 0 {
				_, _, _ = procGdipSetTextRenderingHint.Call(pG, gpTextRenderClearType)
				r.gpG = pG
				r.fonts.smallHeight = r.smallLineHeight()
				_ = r.footerLines()
				_, _, _ = procGdipDeleteGraphics.Call(pG)
				r.gpG = 0
			}
			_, _, _ = procGdipDisposeImage.Call(pImg)
		}
		_, _, _ = procDeleteObject.Call(probeBmp)
	}

	r.fonts.smallHeight = r.smallLineHeight()
	contentBot := r.contentBottom()
	footerH := r.footerHeight()
	logicalH := float64(contentBot + footerH)
	w := int(math.Round(float64(flyoutWidthDip) * r.scale))
	h := int(math.Round(logicalH * r.scale))
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}

	bmi := bitmapInfoHeader{
		biSize:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:    int32(w),
		biHeight:   -int32(h),
		biPlanes:   1,
		biBitCount: 32,
	}
	var bits unsafe.Pointer
	hBmp, _, callErr := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hBmp == 0 || bits == nil {
		return 0, 0, 0, fmt.Errorf("CreateDIBSection flyout(%dx%d): %w", w, h, callErr)
	}
	r.hBmp = hBmp
	r.widthPx = w
	r.heightPx = h
	r.bgra = unsafe.Slice((*byte)(bits), w*h*4)

	// Clear background with opaque colBg (#202020).
	for i := 0; i < len(r.bgra); i += 4 {
		r.bgra[i+0] = colBg.B
		r.bgra[i+1] = colBg.G
		r.bgra[i+2] = colBg.R
		r.bgra[i+3] = 255
	}

	if st, _, _ := procGdipCreateBitmapFromScan0.Call(uintptr(w), uintptr(h), uintptr(w*4), gpPixelFormat32bppARGB, uintptr(bits), uintptr(unsafe.Pointer(&r.gpImg))); st != 0 || r.gpImg == 0 {
		_ = err
		return hBmp, w, h, fmt.Errorf("GdipCreateBitmapFromScan0: %d", st)
	}
	if st, _, _ := procGdipGetImageGraphicsContext.Call(r.gpImg, uintptr(unsafe.Pointer(&r.gpG))); st != 0 || r.gpG == 0 {
		return hBmp, w, h, fmt.Errorf("GdipGetImageGraphicsContext: %d", st)
	}
	_, _, _ = procGdipSetTextRenderingHint.Call(r.gpG, gpTextRenderClearType)

	// Two-pass drawing:
	// Pass 1 renders all pure-Go rasterized vector shapes/fills/icons directly into r.bgra,
	// Pass 2 draws ClearType GDI+ text over those surfaces without GDI+ overwriting shapes.
	// Wait: some shapes (e.g. badges, marks inside buttons) sit next to text rather than under it,
	// except text sits on top of background/cards/buttons/tiles/avatars/footer, so drawing shapes
	// before text works everywhere except hover/pressed overlays or borders that don't cover text.
	r.draw(float32(logicalH))
	return hBmp, w, h, nil
}

func (r *flyoutRenderer) draw(height float32) {
	r.hits = nil
	r.notes = nil

	// Header: title & status on left, open button on right.
	r.caption("Net Switch", r.fonts.title, r.fonts.titlePx, colWhite, flyoutPad, flyoutPad+8.5, 300, gpAlignNear)
	r.fillEllipse(flyoutPad, 40, 7, 7, flyoutToneColor(r.view.Tone))
	r.caption(r.view.Status, r.fonts.body, r.fonts.bodyPx, colSecondary, flyoutPad+13, 43.5, 290, gpAlignNear)
	openAction := FlyoutAction{Key: "open"}
	r.button(flyoutRectF{float32(flyoutWidthDip - flyoutPad - 26), 20.5, 26, 26}, openAction, "Open Net Switch", !r.quitting, colCard, false, 6)
	openColor := colSecondary
	if r.quitting {
		openColor = colFaint
	}
	r.glyph("maximize", float32(flyoutWidthDip-flyoutPad-20), 26.5, 14, openColor)

	if !r.view.Available {
		r.paragraph(r.view.Message, r.fonts.body, r.fonts.bodyPx, colSecondary, flyoutRectF{flyoutPad, flyoutTilesTop, flyoutInner, 36})
		btn := flyoutRectF{flyoutPad, flyoutTilesTop + 48, flyoutInner, 36}
		r.button(btn, openAction, "Open Net Switch", !r.quitting, colAccent, false, 8)
		r.caption("Open Net Switch", r.fonts.label, r.fonts.labelPx, colInk, btn.x, btn.y+18, btn.w, gpAlignCenter)
	} else {
		detail := "Off"
		if r.view.RoutingWanted {
			detail = "On"
		}
		r.tile(flyoutPad, "routing", "Routing", detail, r.view.RoutingWanted, true)
		r.tile(flyoutPad+flyoutTileWidth+8, "combine", r.view.CombineName, r.view.CombineDetail, r.view.CombineOn, r.view.CanCombine)

		r.roundRect(flyoutRectF{flyoutPad, flyoutLinesTop, flyoutInner, float32(flyoutLinesHeight(r.view))}, 8, colCard, colTransparent)
		y := float32(flyoutLinesTop + 12)
		if len(r.view.Lines) == 0 {
			r.caption("No line is set up yet", r.fonts.body, r.fonts.bodyPx, colDim, flyoutPad+12, y+8, flyoutInner-24, gpAlignNear)
		}
		for _, line := range r.view.Lines {
			r.lineRow(line, y)
			y += float32(flyoutLineRowHeight(line) + flyoutLineGap)
		}
		if r.view.MoreLines > 0 {
			r.moreLink(y)
		}

		r.appsHead(float32(flyoutAppsTop(r.view)))
		top := float32(flyoutRowsTop(r.view))
		if len(r.view.Apps) == 0 {
			r.caption("No apps using the connection yet", r.fonts.body, r.fonts.bodyPx, colDim, flyoutPad+2, top+flyoutRowHeight/2.0, flyoutInner-4, gpAlignNear)
		}
		layout := r.layoutApps()
		for i, app := range r.view.Apps {
			r.appRow(app, top+float32(i*(flyoutRowHeight+flyoutRowGap)), layout)
		}
	}

	r.footer(float32(r.contentBottom()), height)
	if r.drawEdge {
		r.strokeOuterEdge(colEdge)
	}
}

func (r *flyoutRenderer) tile(x float32, key, name, detail string, on, enabled bool) {
	action := FlyoutAction{
		Key:      key,
		Endpoint: "/api/" + key,
		Body:     map[string]any{"on": !on},
	}
	fill := colCard
	if on {
		fill = colAccent
	}
	r.button(flyoutRectF{x, flyoutTilesTop, flyoutTileWidth, flyoutTileHeight}, action, name+": "+detail, enabled && !r.quitting && r.pending == "", fill, !on, 8)
	glyphColor := colFaint
	nameColor := colDim
	detailColor := colDim
	if on {
		glyphColor = colInk
		nameColor = colInk
		detailColor = colInkSoft
	} else if enabled {
		glyphColor = colSecondary
		nameColor = colWhite
	}
	glyphName := "merge"
	if key == "routing" {
		glyphName = "power"
	}
	r.glyph(glyphName, x+12, flyoutTilesTop+12, 18, glyphColor)
	r.caption(name, r.fonts.label, r.fonts.labelPx, nameColor, x+12, flyoutTilesTop+48, flyoutTileWidth-24, gpAlignNear)
	r.caption(detail, r.fonts.small, r.fonts.smallPx, detailColor, x+12, flyoutTilesTop+63.5, flyoutTileWidth-24, gpAlignNear)
}

func (r *flyoutRenderer) lineRow(line desktop.FlyoutLine, y float32) {
	colorIdx := line.Color
	if colorIdx < 0 {
		colorIdx = 0
	}
	lineCol := flyoutPalette[colorIdx%len(flyoutPalette)]
	middle := y + 8
	right := float32(flyoutWidthDip - flyoutPad - 12)
	left := float32(flyoutPad + 12)

	dotCol := colDim
	if line.Healthy {
		dotCol = lineCol
	}
	r.fillRoundRect(flyoutRectF{left, middle - 4, 8, 8}, 2, dotCol)

	reading := line.Health
	readingFont := r.fonts.small
	readingPx := r.fonts.smallPx
	readingCol := flyoutToneColor(line.Tone)
	if line.Healthy {
		reading = line.Speed
		readingCol = colWhite
		if line.Speed != "Not measured" {
			readingFont = r.fonts.mono
			readingPx = r.fonts.monoPx
		}
	}
	readingWidth := minFloat32(140, r.measure(reading, readingFont, readingPx))
	r.caption(reading, readingFont, readingPx, readingCol, right-140, middle, 140, gpAlignFar)

	nameLeft := left + 16
	room := right - readingWidth - 12 - nameLeft

	var marks []string
	if line.Main {
		marks = append(marks, "MAIN")
	}
	if line.Metered {
		marks = append(marks, "METERED")
	}
	var marksWidth float32
	for _, m := range marks {
		marksWidth += 6 + r.measure(m, r.fonts.badge, r.fonts.badgePx) + 10
	}
	nameRoom := maxFloat32(40, room-marksWidth)
	nameWidth := minFloat32(nameRoom, r.measure(line.Name, r.fonts.strong, r.fonts.strongPx))
	nameCol := colSecondary
	if line.Healthy {
		nameCol = colWhite
	}
	r.caption(line.Name, r.fonts.strong, r.fonts.strongPx, nameCol, nameLeft, middle, nameRoom, gpAlignNear)

	x := nameLeft + nameWidth
	for _, m := range marks {
		box := flyoutRectF{x + 6, middle - 7, r.measure(m, r.fonts.badge, r.fonts.badgePx) + 10, 14}
		if box.x+box.w > nameLeft+room {
			break
		}
		r.roundRect(box, 4, colTransparent, colHairline)
		r.caption(m, r.fonts.badge, r.fonts.badgePx, colSecondary, box.x, middle, box.w, gpAlignCenter)
		x = box.x + box.w
	}
	detailLeft := x + 8
	detailRoom := nameLeft + room - detailLeft
	if line.Detail != "" && detailRoom > 24 {
		r.caption(line.Detail, r.fonts.small, r.fonts.smallPx, colDim, detailLeft, middle, detailRoom, gpAlignNear)
	}

	if line.Note != "" {
		r.caption(line.Note, r.fonts.small, r.fonts.smallPx, colSecondary, left, y+30, right-left, gpAlignNear)
	} else {
		cell := float32(flyoutInner-24-23*2) / 24.0
		offCol := colUnlitDown
		if line.Healthy {
			offCol = colUnlit
		}
		for i := 0; i < 24; i++ {
			c := offCol
			if i < line.Lit {
				c = lineCol
			}
			r.fillRoundRect(flyoutRectF{left + float32(i)*(cell+2), y + 23, cell, 6}, 1, c)
		}
	}
	r.notes = append(r.notes, flyoutNote{
		bounds: flyoutRectF{flyoutPad, y - 5, flyoutInner, float32(flyoutLineRowHeight(line) + 10)},
		tip:    line.Tip,
	})
}

func (r *flyoutRenderer) moreLink(y float32) {
	text := fmt.Sprintf("+%d more lines", r.view.MoreLines)
	if r.view.MoreLines == 1 {
		text = "+1 more line"
	}
	left := float32(flyoutPad + 12)
	middle := y + flyoutMoreHeight/2.0
	w := r.measure(text, r.fonts.small, r.fonts.smallPx)
	r.button(flyoutRectF{left - 6, middle - 11, w + 12, 22}, FlyoutAction{Key: "more"}, "See every line in Net Switch", !r.quitting, colCard, false, 6)
	c := colAccent
	if r.quitting {
		c = colFaint
	}
	r.caption(text, r.fonts.small, r.fonts.smallPx, c, left, middle, w+20, gpAlignNear)
}

func (r *flyoutRenderer) appsHead(y float32) {
	middle := y + 2 + 8
	r.caption("Busiest apps", r.fonts.strong, r.fonts.strongPx, colSecondary, flyoutPad+2, middle, 200, gpAlignNear)
	w := r.measure("See all", r.fonts.body, r.fonts.bodyPx)
	right := float32(flyoutWidthDip - flyoutPad - 2)
	r.button(flyoutRectF{right - w - 6, middle - 11, w + 12, 22}, FlyoutAction{Key: "all"}, "See all apps in Net Switch", !r.quitting, colBg, false, 6)
	c := colAccent
	if r.quitting {
		c = colFaint
	}
	r.caption("See all", r.fonts.body, r.fonts.bodyPx, c, right-100, middle, 100, gpAlignFar)
}

type flyoutAppLayout struct {
	widths      []float32
	controlLeft float32
	stacked     bool
}

func (r *flyoutRenderer) markWidth(opt desktop.FlyoutOption) float32 {
	if opt.Shared {
		return maxFloat32(12, float32(len(r.view.SharingColors)*5))
	}
	return 6
}

func (r *flyoutRenderer) changeWidth() float32 {
	return r.measure("Change", r.fonts.body, r.fonts.bodyPx) + 12
}

func (r *flyoutRenderer) chosenWidth() float32 {
	var widest float32
	for _, opt := range r.view.Options {
		w := r.measure(opt.Label, r.fonts.small, r.fonts.smallPx) + r.markWidth(opt) + 5
		if w > widest {
			widest = w
		}
	}
	return minFloat32(flyoutMaxChosen, widest+16)
}

func (r *flyoutRenderer) layoutApps() flyoutAppLayout {
	var l flyoutAppLayout
	right := float32(flyoutWidthDip - flyoutPad - 8)
	l.controlLeft = right
	if len(r.view.Options) >= 2 {
		if r.view.CompactChoice {
			count := len(r.view.Options)
			natural := make([]float32, count)
			for i, opt := range r.view.Options {
				natural[i] = r.measure(opt.Label, r.fonts.smallStrong, r.fonts.smallStrongPx) + r.markWidth(opt) + 5 + 14
			}
			maxCtrl := float32(flyoutMaxControl3)
			if count == 2 {
				maxCtrl = flyoutMaxControl2
			}
			capW := widestFitting(natural, maxCtrl-4-2*float32(count-1))
			l.widths = make([]float32, count)
			var total float32 = 4
			for i := 0; i < count; i++ {
				l.widths[i] = minFloat32(capW, natural[i])
				if i > 0 {
					total += 2
				}
				total += l.widths[i]
			}
			l.controlLeft = right - total
		} else {
			l.controlLeft = right - r.changeWidth() - 8 - r.chosenWidth()
		}
	}
	nameLeft := float32(flyoutPad + 8 + 22 + 10)
	speedWidth := r.measure("999 KB/s", r.fonts.monoSmall, r.fonts.monoSmallPx)
	l.stacked = l.controlLeft-10-speedWidth-10-nameLeft < flyoutMinNameRoom
	return l
}

func widestFitting(widths []float32, room float32) float32 {
	sorted := append([]float32(nil), widths...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	var used float32
	for i := 0; i < len(sorted); i++ {
		even := (room - used) / float32(len(sorted)-i)
		if sorted[i] > even {
			return even
		}
		used += sorted[i]
	}
	return math.MaxFloat32
}

func (r *flyoutRenderer) appRow(app desktop.FlyoutApp, y float32, layout flyoutAppLayout) {
	middle := y + flyoutRowHeight/2.0
	r.fillRoundRect(flyoutRectF{flyoutPad, y, flyoutInner, flyoutRowHeight}, 6, colCard)

	left := float32(flyoutPad + 8)
	avatar := flyoutRectF{left, middle - 11, 22, 22}
	avCol := flyoutAvatars[0]
	if app.ColorIndex >= 0 {
		avCol = flyoutAvatars[app.ColorIndex%len(flyoutAvatars)]
	}
	r.fillRoundRect(avatar, 5, avCol)
	r.caption(app.Initial, r.fonts.letter, r.fonts.letterPx, colAvatarInk, avatar.x, middle, avatar.w, gpAlignCenter)

	control := layout.controlLeft
	target := app.Identity
	if target == "" {
		target = app.Path
	}

	if len(r.view.Options) >= 2 && r.view.CompactChoice {
		segment := flyoutRectF{control, middle - 11.5, float32(flyoutWidthDip-flyoutPad-8) - control, 23}
		r.fillRoundRect(segment, 6, colSegmentFill)
		x := segment.x + 2
		for i, opt := range r.view.Options {
			r.appOption(app, opt, flyoutRectF{x, segment.y + 2, layout.widths[i], 19})
			x += layout.widths[i] + 2
		}
		if !app.CanMove {
			r.notes = append(r.notes, flyoutNote{bounds: segment, tip: app.Name + " can\u2019t be moved"})
		}
	} else if len(r.view.Options) >= 2 {
		chosen := r.view.Options[0]
		for _, opt := range r.view.Options {
			if choiceEqual(app.Choice, opt) {
				chosen = opt
				break
			}
		}
		changeW := r.changeWidth()
		pill := flyoutRectF{control, middle - 11.5, r.chosenWidth(), 23}
		r.fillRoundRect(pill, 6, colSegmentFill)
		pillCol := colDim
		if app.CanMove {
			pillCol = colSecondary
		}
		r.markedCaption(chosen, chosen.Label, r.fonts.small, r.fonts.smallPx, pillCol, pill)
		r.notes = append(r.notes, flyoutNote{bounds: pill, tip: app.Name + ": " + chosen.Name})
		changeLeft := float32(flyoutWidthDip-flyoutPad-8) - changeW
		if app.CanMove {
			r.button(flyoutRectF{changeLeft, middle - 11, changeW, 22}, FlyoutAction{Key: "change:" + target}, "Choose the line for "+app.Name+" in Net Switch", !r.quitting, colCard, false, 6)
			c := colAccent
			if r.quitting {
				c = colFaint
			}
			r.caption("Change", r.fonts.body, r.fonts.bodyPx, c, changeLeft, middle, changeW, gpAlignCenter)
		} else {
			r.notes = append(r.notes, flyoutNote{bounds: flyoutRectF{changeLeft, middle - 11, changeW, 22}, tip: app.Name + " can\u2019t be moved"})
		}
	}

	nameLeft := left + 22 + 10
	if layout.stacked {
		nameRoom := control - 10 - nameLeft
		r.caption(app.Name, r.fonts.body, r.fonts.bodyPx, colWhite, nameLeft, middle-7, nameRoom, gpAlignNear)
		r.caption(app.Speed, r.fonts.monoSmall, r.fonts.monoSmallPx, colDim, nameLeft, middle+7.5, nameRoom, gpAlignNear)
	} else {
		speedRight := control - 10
		speedW := r.measure(app.Speed, r.fonts.monoSmall, r.fonts.monoSmallPx)
		r.caption(app.Speed, r.fonts.monoSmall, r.fonts.monoSmallPx, colDim, speedRight-100, middle, 100, gpAlignFar)
		r.caption(app.Name, r.fonts.body, r.fonts.bodyPx, colWhite, nameLeft, middle, speedRight-speedW-10-nameLeft, gpAlignNear)
	}
}

func choiceEqual(choice *string, opt desktop.FlyoutOption) bool {
	if choice == nil {
		return !opt.HasVal
	}
	return opt.HasVal && *choice == opt.Value
}

func (r *flyoutRenderer) appOption(app desktop.FlyoutApp, opt desktop.FlyoutOption, bounds flyoutRectF) {
	selected := choiceEqual(app.Choice, opt)
	enabled := !selected && app.CanMove && !r.quitting && r.pending == ""
	target := app.Identity
	if target == "" {
		target = app.Path
	}
	var lineArg any
	if opt.Send != nil {
		lineArg = *opt.Send
	}
	action := FlyoutAction{
		Key:      "app:" + target + ":" + opt.Value,
		Endpoint: "/api/app-line",
		Body:     map[string]any{"path": target, "line": lineArg},
	}
	hint := "Put " + app.Name + " on the " + opt.Name
	if opt.Shared {
		hint = "Share " + app.Name + "\u2019s new connections between the lines"
	}
	fill := colSegmentFill
	if selected {
		fill = colSelectedFill
	}
	r.button(bounds, action, hint, enabled, fill, false, 4)

	font := r.fonts.small
	fontPx := r.fonts.smallPx
	c := colFaint
	if selected {
		font = r.fonts.smallStrong
		fontPx = r.fonts.smallStrongPx
		if app.CanMove {
			c = colWhite
		} else {
			c = colDim
		}
	} else if enabled {
		c = colDim
	}

	if selected {
		r.markedCaption(opt, opt.Label, font, fontPx, c, bounds)
	} else {
		r.caption(opt.Label, font, fontPx, c, bounds.x+7, bounds.y+bounds.h/2.0, bounds.w-14, gpAlignCenter)
	}
}

func (r *flyoutRenderer) markedCaption(opt desktop.FlyoutOption, text string, font uintptr, px float64, c color.NRGBA, bounds flyoutRectF) {
	mw := r.markWidth(opt)
	room := bounds.w - 14 - mw - 5
	tw := r.measure(text, font, px)
	fits := tw <= room
	shown := tw
	if !fits {
		shown = room
	}
	middle := bounds.y + bounds.h/2.0
	start := bounds.x + (bounds.w-(mw+5+shown))/2.0
	r.drawMark(opt, start, middle)
	boxW := room
	if fits {
		boxW = tw + 12
	}
	r.caption(text, font, px, c, start+mw+5, middle, boxW, gpAlignNear)
}

func (r *flyoutRenderer) drawMark(opt desktop.FlyoutOption, x, middle float32) {
	if !opt.Shared {
		idx := opt.Color
		if idx < 0 {
			idx = 0
		}
		r.fillEllipse(x, middle-3, 6, 6, flyoutPalette[idx%len(flyoutPalette)])
		return
	}
	pill := flyoutRectF{x, middle - 3, r.markWidth(opt), 6}
	colors := r.view.SharingColors
	if len(colors) == 0 {
		colors = []int{0}
	}
	r.fillStripedRoundPill(pill, 3, colors)
}

func (r *flyoutRenderer) footer(y, flyoutHeight float32) {
	h := flyoutHeight - y
	r.fillRect(0, y, flyoutWidthDip, h, colFooterFill)
	r.hLine(0, flyoutWidthDip, y, colStroke)

	c := colDim
	if r.errMsg != "" {
		c = colRed
	} else if r.view.Available && !r.quitting {
		c = flyoutToneColor(r.view.HealthTone)
	}
	textCol := colDim
	if r.errMsg != "" {
		textCol = colRed
	}
	glyphName := "shield"
	if r.errMsg == "" && !r.quitting && r.view.Available && r.view.HealthTone == "info" {
		glyphName = "info"
	}

	middle := y + h/2.0
	if r.footerLines() == 1 {
		r.glyph(glyphName, flyoutPad, middle-6.5, 13, c)
		r.caption(flyoutFooterMessage(r.view, r.errMsg, r.quitting), r.fonts.small, r.fonts.smallPx, textCol, flyoutFooterTextLeft, middle, flyoutFooterTextWidth, gpAlignNear)
	} else {
		r.glyph(glyphName, flyoutPad, y+10+float32(r.smallLineHeight())/2.0-6.5, 13, c)
		r.paragraph(flyoutFooterMessage(r.view, r.errMsg, r.quitting), r.fonts.small, r.fonts.smallPx, textCol, flyoutRectF{flyoutFooterTextLeft, y + 10, flyoutFooterTextWidth, h - 18})
	}
	w := r.measure("Quit", r.fonts.small, r.fonts.smallPx)
	right := float32(flyoutWidthDip - flyoutPad)
	r.button(flyoutRectF{right - w - 6, middle - 11, w + 12, 22}, FlyoutAction{Key: "quit"}, "Quit Net Switch", !r.quitting, colFooterFill, false, 6)
	qc := colSecondary
	if r.quitting {
		qc = colFaint
	}
	r.caption("Quit", r.fonts.small, r.fonts.smallPx, qc, right-60, middle, 60, gpAlignFar)
}

func (r *flyoutRenderer) button(bounds flyoutRectF, action FlyoutAction, hint string, enabled bool, fill color.NRGBA, border bool, radius float32) {
	over := enabled && (r.hover == action.Key || r.keyboard == action.Key)
	if over {
		fill = lightenNRGBA(fill, 0.12)
	}
	strokeCol := colTransparent
	if border {
		strokeCol = colStroke
	}
	r.roundRect(bounds, radius, fill, strokeCol)
	if r.pending == action.Key || r.pressed == action.Key {
		r.roundRect(bounds, radius, color.NRGBA{R: 0, G: 0, B: 0, A: 60}, colTransparent)
	}
	if r.keyboard == action.Key && enabled {
		r.roundRect(flyoutRectF{bounds.x + 1, bounds.y + 1, bounds.w - 2, bounds.h - 2}, maxFloat32(1, radius-1), colTransparent, colWhite)
	}
	if enabled {
		r.hits = append(r.hits, flyoutHit{bounds: bounds, action: action, tip: hint})
	}
}

func flyoutToneColor(tone string) color.NRGBA {
	switch tone {
	case "ok":
		return colGreen
	case "error", "down":
		return colRed
	case "warning", "warn":
		return colWarning
	default:
		return colDim
	}
}

func lightenNRGBA(c color.NRGBA, pct float64) color.NRGBA {
	mix := func(v uint8) uint8 {
		n := float64(v) + (255.0-float64(v))*pct
		if n > 255 {
			return 255
		}
		return uint8(math.Round(n))
	}
	return color.NRGBA{R: mix(c.R), G: mix(c.G), B: mix(c.B), A: c.A}
}

// ------------------------------------------------------------ GDI+ text helpers

func (r *flyoutRenderer) getStringFormat(align int32, wrap bool) uintptr {
	key := uint32(align)
	if wrap {
		key |= 0x100
	}
	if h, ok := r.strFmt[key]; ok {
		return h
	}
	var fmtH uintptr
	if st, _, _ := procGdipCreateStringFormat.Call(0, 0, uintptr(unsafe.Pointer(&fmtH))); st != 0 || fmtH == 0 {
		return 0
	}
	lineAlign := int32(gpAlignCenter)
	flags := int32(gpFormatFlagNoWrap)
	if wrap {
		lineAlign = gpAlignNear
		flags = gpFormatFlagLineLimit
	}
	_, _, _ = procGdipSetStringFormatAlign.Call(fmtH, uintptr(align))
	_, _, _ = procGdipSetStringFormatLineAlign.Call(fmtH, uintptr(lineAlign))
	_, _, _ = procGdipSetStringFormatTrimming.Call(fmtH, gpTrimEllipsisChar)
	_, _, _ = procGdipSetStringFormatFlags.Call(fmtH, uintptr(flags))
	r.strFmt[key] = fmtH
	return fmtH
}

func (r *flyoutRenderer) measure(text string, font uintptr, px float64) float32 {
	if text == "" || r.gpG == 0 || font == 0 {
		return 0
	}
	u := utf16.Encode([]rune(text))
	if len(u) == 0 {
		return 0
	}
	var fmtH uintptr
	if st, _, _ := procGdipCreateStringFormat.Call(0, 0, uintptr(unsafe.Pointer(&fmtH))); st != 0 || fmtH == 0 {
		return float32(len([]rune(text))) * float32(px) * 0.55
	}
	defer func() { _, _, _ = procGdipDeleteStringFormat.Call(fmtH) }()
	_, _, _ = procGdipSetStringFormatAlign.Call(fmtH, gpAlignNear)
	_, _, _ = procGdipSetStringFormatLineAlign.Call(fmtH, gpAlignCenter)
	_, _, _ = procGdipSetStringFormatTrimming.Call(fmtH, gpTrimEllipsisChar)
	_, _, _ = procGdipSetStringFormatFlags.Call(fmtH, gpFormatFlagNoWrap)
	cr := characterRange{First: 0, Length: int32(len(u))}
	_, _, _ = procGdipSetStringFormatMeasurableCharRange.Call(fmtH, 1, uintptr(unsafe.Pointer(&cr)))
	var region uintptr
	if st, _, _ := procGdipCreateRegion.Call(uintptr(unsafe.Pointer(&region))); st != 0 || region == 0 {
		return 0
	}
	defer func() { _, _, _ = procGdipDeleteRegion.Call(region) }()
	room := rectF{X: 0, Y: 0, Width: float32(10000 * r.scale), Height: float32(1000 * r.scale)}
	_, _, _ = procGdipMeasureCharacterRanges.Call(
		r.gpG,
		uintptr(unsafe.Pointer(&u[0])),
		uintptr(len(u)),
		font,
		uintptr(unsafe.Pointer(&room)),
		fmtH,
		1,
		uintptr(unsafe.Pointer(&region)),
	)
	runtime.KeepAlive(u)
	var b rectF
	_, _, _ = procGdipGetRegionBounds.Call(region, r.gpG, uintptr(unsafe.Pointer(&b)))
	logical := float64(b.Width) / r.scale
	return float32(math.Ceil(logical))
}

func (r *flyoutRenderer) caption(text string, font uintptr, px float64, c color.NRGBA, x, y, width float32, align int32) {
	if width <= 0 || r.gpG == 0 || font == 0 || text == "" {
		return
	}
	pad := float32(px / 6.0)
	rect := rectF{
		X:      (x - pad) * float32(r.scale),
		Y:      (y - float32(px)) * float32(r.scale),
		Width:  (width + 2*pad) * float32(r.scale),
		Height: float32(2*px) * float32(r.scale),
	}
	r.drawString(text, font, c, rect, align, false)
}

func (r *flyoutRenderer) paragraph(text string, font uintptr, px float64, c color.NRGBA, bounds flyoutRectF) {
	if bounds.w <= 0 || bounds.h <= 0 || r.gpG == 0 || font == 0 || text == "" {
		return
	}
	pad := float32(px / 6.0)
	rect := rectF{
		X:      (bounds.x - pad) * float32(r.scale),
		Y:      bounds.y * float32(r.scale),
		Width:  (bounds.w + 2*pad) * float32(r.scale),
		Height: bounds.h * float32(r.scale),
	}
	r.drawString(text, font, c, rect, gpAlignNear, true)
}

func (r *flyoutRenderer) drawString(text string, font uintptr, c color.NRGBA, rect rectF, align int32, wrap bool) {
	u := utf16.Encode([]rune(text))
	if len(u) == 0 {
		return
	}
	argb := uint32(c.A)<<24 | uint32(c.R)<<16 | uint32(c.G)<<8 | uint32(c.B)
	var brush uintptr
	if st, _, _ := procGdipCreateSolidFill.Call(uintptr(argb), uintptr(unsafe.Pointer(&brush))); st != 0 || brush == 0 {
		return
	}
	defer func() { _, _, _ = procGdipDeleteBrush.Call(brush) }()
	fmtH := r.getStringFormat(align, wrap)
	_, _, _ = procGdipDrawString.Call(
		r.gpG,
		uintptr(unsafe.Pointer(&u[0])),
		uintptr(len(u)),
		font,
		uintptr(unsafe.Pointer(&rect)),
		fmtH,
		brush,
	)
	runtime.KeepAlive(u)
}

// ------------------------------------------------------------ Pure-Go AA rasterizer

func (r *flyoutRenderer) blendPx(x, y int, c color.NRGBA, cov float64) {
	if x < 0 || x >= r.widthPx || y < 0 || y >= r.heightPx || cov <= 0 || c.A == 0 {
		return
	}
	if cov > 1 {
		cov = 1
	}
	a := (float64(c.A) / 255.0) * cov
	inv := 1.0 - a
	off := (y*r.widthPx + x) * 4
	r.bgra[off+0] = clampByte(float64(r.bgra[off+0])*inv + float64(c.B)*a)
	r.bgra[off+1] = clampByte(float64(r.bgra[off+1])*inv + float64(c.G)*a)
	r.bgra[off+2] = clampByte(float64(r.bgra[off+2])*inv + float64(c.R)*a)
	r.bgra[off+3] = 255
}

func (r *flyoutRenderer) fillRect(x, y, w, h float32, c color.NRGBA) {
	if c.A == 0 || w <= 0 || h <= 0 {
		return
	}
	s := float64(r.scale)
	x0, y0 := float64(x)*s, float64(y)*s
	x1, y1 := float64(x+w)*s, float64(y+h)*s
	minX := max(0, int(math.Floor(x0)))
	maxX := min(r.widthPx-1, int(math.Ceil(x1)))
	minY := max(0, int(math.Floor(y0)))
	maxY := min(r.heightPx-1, int(math.Ceil(y1)))
	for py := minY; py <= maxY; py++ {
		covY := overlap1D(float64(py), float64(py+1), y0, y1)
		if covY <= 0 {
			continue
		}
		for px := minX; px <= maxX; px++ {
			covX := overlap1D(float64(px), float64(px+1), x0, x1)
			if covX > 0 {
				r.blendPx(px, py, c, covX*covY)
			}
		}
	}
}

func (r *flyoutRenderer) hLine(x0, x1, y float32, c color.NRGBA) {
	r.fillRect(x0, y, x1-x0, 1.0/float32(r.scale), c)
}

func (r *flyoutRenderer) strokeOuterEdge(c color.NRGBA) {
	s := float32(r.scale)
	px := 1.0 / s
	r.fillRect(0, 0, flyoutWidthDip, px, c)
	r.fillRect(0, float32(r.heightPx)/s-px, flyoutWidthDip, px, c)
	r.fillRect(0, px, px, float32(r.heightPx)/s-2*px, c)
	r.fillRect(flyoutWidthDip-px, px, px, float32(r.heightPx)/s-2*px, c)
}

func (r *flyoutRenderer) fillRoundRect(bounds flyoutRectF, radius float32, fill color.NRGBA) {
	r.roundRect(bounds, radius, fill, colTransparent)
}

func (r *flyoutRenderer) roundRect(bounds flyoutRectF, radius float32, fill, border color.NRGBA) {
	s := float64(r.scale)
	x0, y0 := float64(bounds.x)*s, float64(bounds.y)*s
	x1, y1 := float64(bounds.x+bounds.w)*s, float64(bounds.y+bounds.h)*s
	rad := float64(radius) * s

	minX := max(0, int(math.Floor(x0))-2)
	maxX := min(r.widthPx-1, int(math.Ceil(x1))+2)
	minY := max(0, int(math.Floor(y0))-2)
	maxY := min(r.heightPx-1, int(math.Ceil(y1))+2)

	if fill.A != 0 {
		cx := (x0 + x1) * 0.5
		cy := (y0 + y1) * 0.5
		hx := (x1 - x0) * 0.5
		hy := (y1 - y0) * 0.5
		radClamped := math.Min(rad, math.Min(hx, hy))
		for py := minY; py <= maxY; py++ {
			for px := minX; px <= maxX; px++ {
				d := sdRoundBox(float64(px)+0.5-cx, float64(py)+0.5-cy, hx, hy, radClamped)
				cov := 0.5 - d
				if cov > 0 {
					r.blendPx(px, py, fill, cov)
				}
			}
		}
	}
	if border.A != 0 {
		inset := 0.5 * s
		bx0, by0 := x0+inset, y0+inset
		bx1, by1 := x1-inset, y1-inset
		cx := (bx0 + bx1) * 0.5
		cy := (by0 + by1) * 0.5
		hx := (bx1 - bx0) * 0.5
		hy := (by1 - by0) * 0.5
		brad := math.Max(0.5*s, float64(radius)*s-0.5*s)
		brad = math.Min(brad, math.Min(hx, hy))
		halfStroke := 0.5 * s
		for py := minY; py <= maxY; py++ {
			for px := minX; px <= maxX; px++ {
				d := math.Abs(sdRoundBox(float64(px)+0.5-cx, float64(py)+0.5-cy, hx, hy, brad)) - halfStroke
				cov := 0.5 - d
				if cov > 0 {
					r.blendPx(px, py, border, cov)
				}
			}
		}
	}
}

func (r *flyoutRenderer) fillStripedRoundPill(bounds flyoutRectF, radius float32, colors []int) {
	s := float64(r.scale)
	x0, y0 := float64(bounds.x)*s, float64(bounds.y)*s
	x1, y1 := float64(bounds.x+bounds.w)*s, float64(bounds.y+bounds.h)*s
	cx := (x0 + x1) * 0.5
	cy := (y0 + y1) * 0.5
	hx := (x1 - x0) * 0.5
	hy := (y1 - y0) * 0.5
	rad := math.Min(float64(radius)*s, math.Min(hx, hy))

	minX := max(0, int(math.Floor(x0))-1)
	maxX := min(r.widthPx-1, int(math.Ceil(x1))+1)
	minY := max(0, int(math.Floor(y0))-1)
	maxY := min(r.heightPx-1, int(math.Ceil(y1))+1)
	step := (x1 - x0) / float64(len(colors))

	for py := minY; py <= maxY; py++ {
		for px := minX; px <= maxX; px++ {
			d := sdRoundBox(float64(px)+0.5-cx, float64(py)+0.5-cy, hx, hy, rad)
			cov := 0.5 - d
			if cov <= 0 {
				continue
			}
			idx := int((float64(px) + 0.5 - x0) / step)
			if idx < 0 {
				idx = 0
			}
			if idx >= len(colors) {
				idx = len(colors) - 1
			}
			colIdx := colors[idx]
			if colIdx < 0 {
				colIdx = 0
			}
			r.blendPx(px, py, flyoutPalette[colIdx%len(flyoutPalette)], cov)
		}
	}
}

func (r *flyoutRenderer) fillEllipse(x, y, w, h float32, c color.NRGBA) {
	s := float64(r.scale)
	cx := (float64(x) + float64(w)*0.5) * s
	cy := (float64(y) + float64(h)*0.5) * s
	rad := float64(w) * 0.5 * s
	minX := max(0, int(math.Floor(cx-rad))-1)
	maxX := min(r.widthPx-1, int(math.Ceil(cx+rad))+1)
	minY := max(0, int(math.Floor(cy-rad))-1)
	maxY := min(r.heightPx-1, int(math.Ceil(cy+rad))+1)
	for py := minY; py <= maxY; py++ {
		for px := minX; px <= maxX; px++ {
			dx := float64(px) + 0.5 - cx
			dy := float64(py) + 0.5 - cy
			cov := 0.5 - (math.Hypot(dx, dy) - rad)
			if cov > 0 {
				r.blendPx(px, py, c, cov)
			}
		}
	}
}

// ------------------------------------------------------------ Lucide 24x24 glyphs

type pt2 struct{ x, y float64 }

func (r *flyoutRenderer) glyph(name string, gx, gy, size float32, c color.NRGBA) {
	var segs [][2]pt2
	var arcs []struct {
		cx, cy, rad, a0Deg, a1Deg float64
	}
	var circles []struct {
		cx, cy, rad float64
	}
	addSeg := func(x0, y0, x1, y1 float64) {
		segs = append(segs, [2]pt2{{x0, y0}, {x1, y1}})
	}
	addBezier := func(x0, y0, x1, y1, x2, y2, x3, y3 float64) {
		const steps = 14
		prev := pt2{x0, y0}
		for i := 1; i <= steps; i++ {
			t := float64(i) / steps
			it := 1 - t
			p := pt2{
				x: it*it*it*x0 + 3*it*it*t*x1 + 3*it*t*t*x2 + t*t*t*x3,
				y: it*it*it*y0 + 3*it*it*t*y1 + 3*it*t*t*y2 + t*t*t*y3,
			}
			segs = append(segs, [2]pt2{prev, p})
			prev = p
		}
	}

	switch name {
	case "power":
		addSeg(12, 2, 12, 12)
		arcs = append(arcs, struct{ cx, cy, rad, a0Deg, a1Deg float64 }{12, 13, 9, -45, 225})
	case "merge":
		addSeg(8, 6, 12, 2)
		addSeg(12, 2, 16, 6)
		addSeg(12, 2, 12, 12.3)
		arcs = append(arcs, struct{ cx, cy, rad, a0Deg, a1Deg float64 }{8, 12.3, 4, 0, 45})
		addSeg(10.83, 15.13, 4, 22)
		addSeg(20, 22, 15, 17)
	case "maximize":
		addSeg(15, 3, 21, 3)
		addSeg(21, 3, 21, 9)
		addSeg(21, 3, 14, 10)
		addSeg(9, 21, 3, 21)
		addSeg(3, 21, 3, 15)
		addSeg(3, 21, 10, 14)
	case "shield":
		addBezier(20, 13, 20, 18, 16.5, 20.5, 12.34, 21.95)
		addBezier(11.66, 21.94, 7.5, 20.5, 4, 18, 4, 13)
		addSeg(4, 13, 4, 6)
		addBezier(4, 6, 4, 5.45, 4.45, 5, 5, 5)
		addBezier(5, 5, 7, 5, 9.5, 3.8, 11.24, 2.28)
		addBezier(11.24, 2.28, 11.7, 1.9, 12.3, 1.9, 12.76, 2.28)
		addBezier(12.76, 2.28, 14.51, 3.81, 17, 5, 19, 5)
		addBezier(19, 5, 19.55, 5, 20, 5.45, 20, 6)
		addSeg(20, 6, 20, 13)
		addSeg(9, 12, 11, 14)
		addSeg(11, 14, 15, 10)
	case "info":
		circles = append(circles, struct{ cx, cy, rad float64 }{12, 12, 10})
		addSeg(12, 16, 12, 12)
		addSeg(12, 8, 12.01, 8)
	}

	s := float64(r.scale)
	x0 := float64(gx) * s
	y0 := float64(gy) * s
	sz := float64(size) * s
	unitScale := sz / 24.0
	halfStroke := 1.0 * unitScale

	minX := max(0, int(math.Floor(x0-halfStroke))-1)
	maxX := min(r.widthPx-1, int(math.Ceil(x0+sz+halfStroke))+1)
	minY := max(0, int(math.Floor(y0-halfStroke))-1)
	maxY := min(r.heightPx-1, int(math.Ceil(y0+sz+halfStroke))+1)

	for py := minY; py <= maxY; py++ {
		uy := (float64(py) + 0.5 - y0) / unitScale
		for px := minX; px <= maxX; px++ {
			ux := (float64(px) + 0.5 - x0) / unitScale
			minDist := 1e9
			for _, seg := range segs {
				d := distToSeg(ux, uy, seg[0].x, seg[0].y, seg[1].x, seg[1].y)
				if d < minDist {
					minDist = d
				}
			}
			for _, arc := range arcs {
				d := distToArc(ux, uy, arc.cx, arc.cy, arc.rad, arc.a0Deg, arc.a1Deg)
				if d < minDist {
					minDist = d
				}
			}
			for _, cir := range circles {
				d := math.Abs(math.Hypot(ux-cir.cx, uy-cir.cy) - cir.rad)
				if d < minDist {
					minDist = d
				}
			}
			pxDist := (minDist - 1.0) * unitScale
			cov := 0.5 - pxDist
			if cov > 0 {
				r.blendPx(px, py, c, cov)
			}
		}
	}
}

func sdRoundBox(px, py, bx, by, r float64) float64 {
	qx := math.Abs(px) - bx + r
	qy := math.Abs(py) - by + r
	return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - r
}

func overlap1D(a0, a1, b0, b1 float64) float64 {
	lo := math.Max(a0, b0)
	hi := math.Min(a1, b1)
	if hi <= lo {
		return 0
	}
	return hi - lo
}

func distToSeg(px, py, x0, y0, x1, y1 float64) float64 {
	dx, dy := x1-x0, y1-y0
	l2 := dx*dx + dy*dy
	if l2 == 0 {
		return math.Hypot(px-x0, py-y0)
	}
	t := ((px-x0)*dx + (py-y0)*dy) / l2
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	return math.Hypot(px-(x0+t*dx), py-(y0+t*dy))
}

func distToArc(px, py, cx, cy, rad, a0Deg, a1Deg float64) float64 {
	// Angles in screen coordinates (0 = +X, 90 = +Y clockwise).
	ang := math.Atan2(py-cy, px-cx) * 180.0 / math.Pi
	for ang < a0Deg {
		ang += 360
	}
	for ang > a0Deg+360 {
		ang -= 360
	}
	if ang <= a1Deg {
		return math.Abs(math.Hypot(px-cx, py-cy) - rad)
	}
	r0 := a0Deg * math.Pi / 180.0
	r1 := a1Deg * math.Pi / 180.0
	d0 := math.Hypot(px-(cx+rad*math.Cos(r0)), py-(cy+rad*math.Sin(r0)))
	d1 := math.Hypot(px-(cx+rad*math.Cos(r1)), py-(cy+rad*math.Sin(r1)))
	return math.Min(d0, d1)
}

func clampByte(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(math.Round(v))
}

func minFloat32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func maxFloat32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}
