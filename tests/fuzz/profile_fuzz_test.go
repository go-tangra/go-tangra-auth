package fuzz

import (
	"bytes"
	"image"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
)

func seedAvatars(f *testing.F) {
	f.Helper()
	entries, err := os.ReadDir("testdata/avatars")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("testdata/avatars", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0x89, 'P', 'N', 'G'})
	f.Add([]byte{0xff, 0xd8, 0xff})
	f.Add([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "))
}

// FuzzAvatarDecode: the avatar pipeline never panics, never returns anything
// but a square JPEG within the configured edge, and refuses everything that
// is not a decodable PNG/JPEG/WebP within the pixel cap.
func FuzzAvatarDecode(f *testing.F) {
	seedAvatars(f)
	limits := user.AvatarLimits{MaxBytes: 1 << 20, MaxPixels: 512 * 512, Size: 32, Concurrency: 4}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := user.NormaliseAvatar(bytes.NewReader(data), limits)
		if err != nil {
			if out != nil {
				t.Fatal("bytes returned with an error")
			}
			return
		}
		cfg, format, err := image.DecodeConfig(bytes.NewReader(out))
		if err != nil || format != "jpeg" || cfg.Width != cfg.Height || cfg.Width > 32 || cfg.Width == 0 {
			t.Fatalf("output must be a small square JPEG: %+v %s %v", cfg, format, err)
		}
		if bytes.Contains(out, []byte{0xff, 0xe1}) {
			t.Fatal("APP1 (EXIF) marker in output")
		}
	})
}

// FuzzPhone: normalisation never panics and every accepted value is E.164.
func FuzzPhone(f *testing.F) {
	for _, s := range []string{"+385911234567", "+1 (415) 555-0100", "", "0044", "+", "++1", "+1234", strings.Repeat("9", 40), "+38591\u200b1234567"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := user.NormalizePhone(s)
		if err != nil {
			if out != "" {
				t.Fatal("value returned with an error")
			}
			return
		}
		if out == "" {
			if strings.TrimSpace(s) != "" {
				t.Fatalf("non-empty input %q normalised to empty", s)
			}
			return
		}
		if out[0] != '+' || len(out) < 8 || len(out) > 16 || out[1] == '0' {
			t.Fatalf("accepted %q → %q", s, out)
		}
		for _, r := range out[1:] {
			if r < '0' || r > '9' {
				t.Fatalf("non-digit in %q", out)
			}
		}
	})
}

// FuzzName: accepted names are trimmed, bounded and free of control characters.
func FuzzName(f *testing.F) {
	for _, s := range []string{"Dana", " Kovač ", "O'Brien", "李", "a\x00b", strings.Repeat("x", 101), "\t", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := user.ValidateName(s)
		if err != nil {
			return
		}
		if len(out) > user.NameMax || out != strings.TrimSpace(out) {
			t.Fatalf("accepted %q → %q", s, out)
		}
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("control character in %q", out)
			}
		}
	})
}
