package user

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const corpus = "../../tests/fuzz/testdata/avatars"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testLimits() AvatarLimits {
	return AvatarLimits{MaxBytes: 2 << 20, MaxPixels: 4096 * 4096, Size: 64, Concurrency: 2}
}

func TestAvatarNormaliseAcceptsAndStrips(t *testing.T) {
	for _, name := range []string{"valid.png", "valid.jpg", "valid.webp", "exif-gps.jpg", "wide-1000x400.png"} {
		out, err := NormaliseAvatar(bytes.NewReader(fixture(t, name)), testLimits())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cfg, format, err := image.DecodeConfig(bytes.NewReader(out))
		if err != nil || format != "jpeg" || cfg.Width != 64 || cfg.Height != 64 {
			t.Fatalf("%s: output must be a 64×64 JPEG: %+v %s %v", name, cfg, format, err)
		}
		if bytes.Contains(out, []byte("Exif")) || bytes.Contains(out, []byte{0xff, 0xe1}) {
			t.Fatalf("%s: EXIF survived re-encoding", name)
		}
		if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A 1000×400 source is centre-cropped: the output is opaque and square, and the
	// left/right edges come from the middle of the source (gradient in red).
	out, _ := NormaliseAvatar(bytes.NewReader(fixture(t, "wide-1000x400.png")), testLimits())
	img, _ := jpeg.Decode(bytes.NewReader(out))
	l, _, _, _ := img.At(0, 32).RGBA()
	r, _, _, _ := img.At(63, 32).RGBA()
	if l>>8 < 60 || r>>8 > 200 {
		t.Fatalf("centre crop expected (left red=%d right red=%d)", l>>8, r>>8)
	}
	// Transparent pixels are composited onto white.
	out, _ = NormaliseAvatar(bytes.NewReader(fixture(t, "valid.png")), testLimits())
	img, _ = jpeg.Decode(bytes.NewReader(out))
	_, _, b, _ := img.At(2, 2).RGBA()
	if b>>8 < 150 {
		t.Fatalf("alpha must be composited onto white, blue=%d", b>>8)
	}
}

func TestAvatarNormaliseRefuses(t *testing.T) {
	cases := map[string]error{
		"html-as.png":          ErrUnsupportedType,
		"bomb-20000x20000.png": ErrTooLargeDimensions,
		"truncated.jpg":        ErrDecodeFailed,
	}
	for name, want := range cases {
		_, err := NormaliseAvatar(bytes.NewReader(fixture(t, name)), testLimits())
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", name, err, want)
		}
	}
	// GIF and SVG are not accepted even when well-formed.
	gif := []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")
	if _, err := NormaliseAvatar(bytes.NewReader(gif), testLimits()); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("gif: %v", err)
	}
	if _, err := NormaliseAvatar(bytes.NewReader([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)), testLimits()); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("svg: %v", err)
	}
	// Over the byte limit is refused before decoding.
	big := append(fixture(t, "valid.png"), make([]byte, 3<<20)...)
	if _, err := NormaliseAvatar(bytes.NewReader(big), testLimits()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if _, err := NormaliseAvatar(bytes.NewReader(nil), testLimits()); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("empty: %v", err)
	}
}

// The bomb is refused on its header: the decoder must never be reached.
func TestAvatarBombNeverDecodes(t *testing.T) {
	var decoded atomic.Int32
	l := testLimits()
	l.onDecode = func() { decoded.Add(1) }
	if _, err := NormaliseAvatar(bytes.NewReader(fixture(t, "bomb-20000x20000.png")), l); !errors.Is(err, ErrTooLargeDimensions) {
		t.Fatal(err)
	}
	if decoded.Load() != 0 {
		t.Fatal("full decode attempted on an oversized header")
	}
}

func TestAvatarConcurrencyLimit(t *testing.T) {
	l := testLimits()
	l.Concurrency = 1
	var inFlight, peak atomic.Int32
	l.onDecode = func() {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inFlight.Add(-1)
	}
	src := fixture(t, "valid.jpg")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := NormaliseAvatar(bytes.NewReader(src), l); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if peak.Load() > 1 {
		t.Fatalf("decodes in flight peaked at %d", peak.Load())
	}
}

func TestAvatarSetAndRemove(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tidP, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tidP, Email: "dana@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u2", TenantID: tidP, Email: "bob@x.test", Status: "active"})
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	av := NewAvatars(ms, aw, testLimits())
	self := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tidP}
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tidP, Roles: []string{"admin"}}
	url1, err := av.Set(ctx, self, "u1", bytes.NewReader(fixture(t, "valid.png")))
	if err != nil || url1 == "" {
		t.Fatal(url1, err)
	}
	url2, err := av.Set(ctx, self, "u1", bytes.NewReader(fixture(t, "valid.jpg")))
	if err != nil || url2 == url1 {
		t.Fatalf("a new picture must have a new address: %s %s %v", url1, url2, err)
	}
	u, _ := ms.User(ctx, tidP, "u1")
	if _, err := av.Get(ctx, self, "u1", *u.AvatarID); err != nil {
		t.Fatal(err)
	}
	// Stale hash, other user's id, unauthorised writer.
	if _, err := av.Get(ctx, self, "u1", "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := av.Set(ctx, self, "u2", bytes.NewReader(fixture(t, "valid.jpg"))); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member editing another: %v", err)
	}
	if err := av.Remove(ctx, admin, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := av.Remove(ctx, admin, "u1"); err != nil { // idempotent
		t.Fatal(err)
	}
	u, _ = ms.User(ctx, tidP, "u1")
	if u.AvatarID != nil {
		t.Fatal("avatar pointer must be cleared")
	}
	if _, err := av.Set(ctx, self, "u1", bytes.NewReader(fixture(t, "html-as.png"))); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("html: %v", err)
	}
	aw.Flush()
	updated, removed := 0, 0
	for _, r := range ms.AuditRows {
		if r.Outcome != "ok" {
			continue
		}
		switch r.EventType {
		case string(audit.AvatarUpdated):
			updated++
		case string(audit.AvatarRemoved):
			removed++
		}
	}
	if updated != 2 || removed != 1 {
		t.Fatalf("audit updated=%d removed=%d", updated, removed)
	}
}
