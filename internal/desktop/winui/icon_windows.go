//go:build windows

package winui

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/desktop"
)

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

type winIconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

// CreateHIcon renders view at size x size pixels into a Win32 HICON handle.
// Callers must release the returned handle with DestroyHIcon.
func CreateHIcon(view desktop.TrayView, size int) (uintptr, error) {
	if size < 1 {
		size = 16
	}
	img := desktop.PaintIconNRGBA(view, size)

	bmi := bitmapInfoHeader{
		biSize:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:    int32(size),
		biHeight:   -int32(size), // top-down DIB
		biPlanes:   1,
		biBitCount: 32,
	}
	var bits unsafe.Pointer
	hColor, _, err := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hColor == 0 || bits == nil {
		return 0, fmt.Errorf("CreateDIBSection(%d): %w", size, err)
	}
	defer func() { _, _, _ = procDeleteObject.Call(hColor) }()

	dst := unsafe.Slice((*byte)(bits), size*size*4)
	src := img.Pix
	maskStride := ((size + 15) / 16) * 2
	mask := make([]byte, maskStride*size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			off := (y*size + x) * 4
			r, g, b, a := src[off], src[off+1], src[off+2], src[off+3]
			dst[off+0] = b
			dst[off+1] = g
			dst[off+2] = r
			dst[off+3] = a
			if a == 0 {
				mask[y*maskStride+x/8] |= byte(0x80 >> (x % 8))
			}
		}
	}

	hMask, _, err := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	runtime.KeepAlive(mask)
	if hMask == 0 {
		return 0, fmt.Errorf("CreateBitmap mask(%d): %w", size, err)
	}
	defer func() { _, _, _ = procDeleteObject.Call(hMask) }()

	ii := winIconInfo{
		fIcon:    1,
		hbmMask:  hMask,
		hbmColor: hColor,
	}
	hIcon, _, err := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if hIcon == 0 {
		return 0, fmt.Errorf("CreateIconIndirect(%d): %w", size, err)
	}
	return hIcon, nil
}

// DestroyHIcon releases an HICON created by CreateHIcon.
func DestroyHIcon(hIcon uintptr) {
	if hIcon != 0 {
		_, _, _ = procDestroyIcon.Call(hIcon)
	}
}
