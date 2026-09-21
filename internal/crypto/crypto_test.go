package crypto

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestArgon2idHashVerifyAndRehash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple", DefaultParams)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("%q %v", h, err)
	}
	ok, rehash, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok || rehash {
		t.Fatalf("verify %v %v %v", ok, rehash, err)
	}
	ok, _, err = VerifyPassword("wrong", h)
	if err != nil || ok {
		t.Fatal("wrong password accepted")
	}
	weak, _ := HashPassword("pw", Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	ok, rehash, _ = VerifyPassword("pw", weak)
	if !ok || !rehash {
		t.Fatal("older parameters must request a rehash")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$YQ$YQ", "$argon2id$v=19$m=x,t=2,p=1$YQ$YQ", "$argon2id$v=19$m=19456,t=2,p=1$notb64!$YQ", "$argon2id$v=19$m=19456,t=2,p=1$YQ"} {
		if _, _, err := VerifyPassword("pw", bad); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
	if _, err := HashPassword("", DefaultParams); err == nil {
		t.Fatal("empty password must fail")
	}
}

func TestEnvelope(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	env, err := NewEnvelope(kek)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := env.Encrypt([]byte("totp-seed"), []byte("user:u1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("totp-seed")) {
		t.Fatal("plaintext visible")
	}
	pt, err := env.Decrypt(ct, []byte("user:u1"))
	if err != nil || string(pt) != "totp-seed" {
		t.Fatalf("%q %v", pt, err)
	}
	if _, err := env.Decrypt(ct, []byte("user:u2")); err == nil {
		t.Fatal("wrong associated data must fail")
	}
	ct[len(ct)-1] ^= 1
	if _, err := env.Decrypt(ct, []byte("user:u1")); err == nil {
		t.Fatal("tampering must fail")
	}
	if _, err := env.Decrypt([]byte("short"), nil); err == nil {
		t.Fatal("short ciphertext must fail")
	}
	if _, err := NewEnvelope([]byte("bad")); err == nil {
		t.Fatal("kek length")
	}
	other, _ := NewEnvelope(bytes.Repeat([]byte{9}, 32))
	ct2, _ := env.Encrypt([]byte("x"), nil)
	if _, err := other.Decrypt(ct2, nil); err == nil {
		t.Fatal("different KEK must fail")
	}
}

func TestHelpers(t *testing.T) {
	if !ConstantTimeEqual("a", "a") || ConstantTimeEqual("a", "b") || ConstantTimeEqual("a", "ab") {
		t.Fatal("constant time compare")
	}
	tok, err := RandomToken(32)
	if err != nil || len(tok) < 43 {
		t.Fatalf("%q %v", tok, err)
	}
	if h1, h2 := HashToken("abc"), HashToken("abc"); h1 != h2 || len(h1) != 64 || HashToken("abd") == h1 {
		t.Fatal("token hash")
	}
	start := time.Now()
	PadTo(start, 30*time.Millisecond)
	if time.Since(start) < 30*time.Millisecond {
		t.Fatal("PadTo returned early")
	}
	PadTo(time.Now().Add(-time.Second), 10*time.Millisecond) // already past: returns immediately
}
