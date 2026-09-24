package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Key states (data-model.md).
const (
	StateActive   = "active"
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

func keyAD(kid string) []byte { return []byte("signing_key:" + kid) }

// GenerateKey creates an Ed25519 signing key whose private half is sealed
// with the envelope (bound to the kid). The kid is derived from the public key.
func GenerateKey(env *crypto.Envelope, now time.Time) (store.SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(crypto.Rand())
	if err != nil {
		return store.SigningKey{}, err
	}
	sum := sha256.Sum256(pub)
	kid := base64.RawURLEncoding.EncodeToString(sum[:12])
	enc, err := env.Encrypt(priv, keyAD(kid))
	if err != nil {
		return store.SigningKey{}, err
	}
	return store.SigningKey{KID: kid, PublicKey: pub, PrivateEnc: enc, State: StateActive, CreatedAt: now}, nil
}

// OpenKey unseals the private key and checks it matches the stored public key.
func OpenKey(env *crypto.Envelope, k store.SigningKey) (ed25519.PrivateKey, error) {
	raw, err := env.Decrypt(k.PrivateEnc, keyAD(k.KID))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("token: sealed key has wrong size")
	}
	priv := ed25519.PrivateKey(raw)
	if !ed25519.PublicKey(k.PublicKey).Equal(priv.Public()) {
		return nil, errors.New("token: sealed key does not match public key")
	}
	return priv, nil
}
