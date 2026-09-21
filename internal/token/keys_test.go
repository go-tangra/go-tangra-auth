package token

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/crypto"
)

func TestGenerateAndOpenKey(t *testing.T) {
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{7}, 32))
	k, err := GenerateKey(env, time.Now())
	if err != nil || k.KID == "" || k.State != StateActive || len(k.PublicKey) != ed25519.PublicKeySize {
		t.Fatal(k, err)
	}
	if bytes.Contains(k.PrivateEnc, k.PublicKey[:8]) {
		t.Fatal("private material must be sealed")
	}
	priv, err := OpenKey(env, k)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	if !ed25519.Verify(k.PublicKey, msg, ed25519.Sign(priv, msg)) {
		t.Fatal("signature")
	}
	// Wrong KEK, wrong kid binding and a swapped public key are all refused.
	other, _ := crypto.NewEnvelope(bytes.Repeat([]byte{8}, 32))
	if _, err := OpenKey(other, k); err == nil {
		t.Fatal("wrong kek")
	}
	k2 := k
	k2.KID = "other"
	if _, err := OpenKey(env, k2); err == nil {
		t.Fatal("kid binding")
	}
	k3, _ := GenerateKey(env, time.Now())
	k3.PrivateEnc = k.PrivateEnc
	k3.KID = k.KID
	if _, err := OpenKey(env, k3); err == nil {
		t.Fatal("public key mismatch")
	}
}
