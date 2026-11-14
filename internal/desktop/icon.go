package desktop

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
)

var (
	iconPanel = color.NRGBA{R: 0x14, G: 0x16, B: 0x19, A: 0xff}
	iconGray  = color.NRGBA{R: 0xa8, G: 0xad, B: 0xb3, A: 0xff}
	iconLines = []color.NRGBA{
		{R: 0xf0, G: 0xb2, B: 0x3e, A: 0xff},
		{R: 0x4c, G: 0xc3, B: 0xe8, A: 0xff},
		{R: 0xb3, G: 0x94, B: 0xff, A: 0xff},
		{R: 0xf5, G: 0x84, B: 0xc8, A: 0xff},
		{R: 0xb9, G: 0xdc, B: 0x58, A: 0xff},
		{R: 0x7f, G: 0x99, B: 0xff, A: 0xff},
	}
)

// PaintIconNRGBA renders the tray icon at size x size pixels matching the
// geometry and palette of the Net Switch favicon and Windows tray icon.
func PaintIconNRGBA(view TrayView, size int) *image.NRGBA {
	if size < 1 {
		size = 16
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.SetNRGBA(x, y, iconPanel)
		}
	}
	rows := TrayRows(view)
	cell := max(2, size/8)
	gap := max(1, size/16)
	height := max(2, size*3/16)
	rowGap := gap
	if len(rows) == 2 {
		height = max(3, size/4)
		rowGap = 2 * gap
	}
	left := (size - (TrayCells*cell + (TrayCells-1)*gap)) / 2
	top := (size - (len(rows)*height + (len(rows)-1)*rowGap)) / 2
	for r, row := range rows {
		base := iconGray
		if view.Routing {
			base = iconLines[r%len(iconLines)]
		}
		var unlit color.NRGBA
		if row.Available {
			unlit = blendOverOpaque(iconPanel, base, 70)
		} else {
			unlit = blendOverOpaque(iconPanel, iconGray, 40)
		}
		ry := top + r*(height+rowGap)
		for i := 0; i < TrayCells; i++ {
			c := unlit
			if i < row.Lit {
				c = base
			}
			rx := left + i*(cell+gap)
			fillRectNRGBA(img, rx, ry, cell, height, c)
		}
	}
	roundCornersNRGBA(img, max(2, size/8))
	return img
}

// PaintIconPNG encodes the tray icon at size x size as PNG bytes.
func PaintIconPNG(view TrayView, size int) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, PaintIconNRGBA(view, size)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func blendOverOpaque(bg, fg color.NRGBA, alpha uint8) color.NRGBA {
	a := uint32(alpha)
	inv := 255 - a
	return color.NRGBA{
		R: uint8((uint32(fg.R)*a + uint32(bg.R)*inv + 127) / 255),
		G: uint8((uint32(fg.G)*a + uint32(bg.G)*inv + 127) / 255),
		B: uint8((uint32(fg.B)*a + uint32(bg.B)*inv + 127) / 255),
		A: 0xff,
	}
}

func fillRectNRGBA(img *image.NRGBA, x, y, w, h int, c color.NRGBA) {
	b := img.Bounds()
	x0, y0 := max(b.Min.X, x), max(b.Min.Y, y)
	x1, y1 := min(b.Max.X, x+w), min(b.Max.Y, y+h)
	for py := y0; py < y1; py++ {
		for px := x0; px < x1; px++ {
			img.SetNRGBA(px, py, c)
		}
	}
}

func roundCornersNRGBA(img *image.NRGBA, radius int) {
	lastX := img.Bounds().Max.X - 1
	lastY := img.Bounds().Max.Y - 1
	clear := color.NRGBA{}
	for y := 0; y < radius; y++ {
		for x := 0; x < radius-y; x++ {
			img.SetNRGBA(x, y, clear)
			img.SetNRGBA(lastX-x, y, clear)
			img.SetNRGBA(x, lastY-y, clear)
			img.SetNRGBA(lastX-x, lastY-y, clear)
		}
	}
}
