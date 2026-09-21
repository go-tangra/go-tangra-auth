//go:build ignore

// Generates the avatar corpus used by the avatar unit and fuzz tests:
//
//	go run gen.go
//
// valid.png / valid.jpg (small photos with alpha and without), html-as.png (an
// HTML document with a .png name), bomb-20000x20000.png (a genuine PNG header
// declaring 20000×20000 pixels with no pixel data), truncated.jpg (a JPEG cut
// in half), exif-gps.jpg (JPEG carrying an APP1 EXIF segment with a GPS IFD),
// wide-1000x400.png (for the centre-crop test).
package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
)

func photo(w, h int, alpha bool) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			a := uint8(255)
			if alpha && x < w/2 {
				a = 64
			}
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 128, A: a}) // #nosec G115
		}
	}
	return img
}

func write(name string, b []byte) {
	if err := os.WriteFile(name, b, 0o644); err != nil { // #nosec G306 -- test fixtures
		panic(err)
	}
}

func main() {
	var buf bytes.Buffer
	_ = png.Encode(&buf, photo(96, 96, true))
	write("valid.png", buf.Bytes())

	buf.Reset()
	_ = jpeg.Encode(&buf, photo(120, 80, false), &jpeg.Options{Quality: 80})
	write("valid.jpg", buf.Bytes())
	half := append([]byte(nil), buf.Bytes()[:buf.Len()/2]...)
	write("truncated.jpg", half)

	buf.Reset()
	_ = png.Encode(&buf, photo(1000, 400, false))
	write("wide-1000x400.png", buf.Bytes())

	write("html-as.png", []byte("<!doctype html><html><body><script>alert(1)</script></body></html>"))

	// PNG signature + IHDR declaring 20000×20000; the decoder must refuse on the
	// header alone (DecodeConfig) without allocating the 1.6 GB frame.
	hdr := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 20000)
	binary.BigEndian.PutUint32(ihdr[4:], 20000)
	ihdr[8], ihdr[9], ihdr[10], ihdr[11], ihdr[12] = 8, 6, 0, 0, 0
	chunk := func(typ string, data []byte) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(len(data))) // #nosec G115
		body := append([]byte(typ), data...)
		out = append(out, body...)
		crc := make([]byte, 4)
		binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(body))
		return append(out, crc...)
	}
	write("bomb-20000x20000.png", append(append(hdr, chunk("IHDR", ihdr)...), chunk("IEND", nil)...))

	// JPEG with an APP1 EXIF segment holding a GPS IFD pointer.
	buf.Reset()
	_ = jpeg.Encode(&buf, photo(64, 64, false), &jpeg.Options{Quality: 80})
	j := buf.Bytes()
	exif := []byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08\x00\x01\x88\x25\x00\x04\x00\x00\x00\x01\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x01\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00")
	app1 := append([]byte{0xff, 0xe1, byte((len(exif) + 2) >> 8), byte(len(exif) + 2)}, exif...)
	out := append([]byte{}, j[:2]...)
	out = append(out, app1...)
	out = append(out, j[2:]...)
	write("exif-gps.jpg", out)
}
