package password

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
)

func TestCheckPolicy(t *testing.T) {
	p := tenant.DefaultPolicy()
	if err := Check(p, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for pw, want := range map[string]error{"short": ErrTooShort, strings.Repeat("a", 12): ErrWeak, strings.Repeat(" ", 12): ErrWeak, strings.Repeat("x", 1025): ErrTooLong} {
		if err := Check(p, pw); !errors.Is(err, want) {
			t.Errorf("%q: %v", pw[:5], err)
		}
	}
	p.PasswordMinLength = 8
	if err := Check(p, "eightch8"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRehashAndDummy(t *testing.T) {
	h, err := Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, re := Verify("correct horse battery", h); !ok || re {
		t.Fatal(ok, re)
	}
	if ok, _ := Verify("wrong", h); ok {
		t.Fatal("wrong accepted")
	}
	old, _ := crypto.HashPassword("pw-with-old-params", crypto.Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	if ok, re := Verify("pw-with-old-params", old); !ok || !re {
		t.Fatalf("rehash expected: %v %v", ok, re)
	}
	if ok, _ := Verify("anything", ""); ok {
		t.Fatal("dummy must never verify")
	}
	if ok, _ := Verify("x", "not-a-phc-string"); ok {
		t.Fatal("corrupt hash")
	}
	// Unknown-account and wrong-password paths cost about the same.
	start := time.Now()
	Verify("anything", "")
	dummy := time.Since(start)
	start = time.Now()
	Verify("anything", h)
	real := time.Since(start)
	if ratio := float64(dummy) / float64(real); ratio < 0.5 || ratio > 2 {
		t.Fatalf("work factor differs: dummy=%v real=%v", dummy, real)
	}
	start = time.Now()
	Pad(start)
	if time.Since(start) < PadDuration {
		t.Fatal("pad too short")
	}
}
