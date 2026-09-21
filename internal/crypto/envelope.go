package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// Envelope encrypts small secrets (TOTP seeds, signing keys) with a per-item
// data key wrapped by the KEK; the KEK never touches the database (SR-004).
// Layout: nonce(12) | wrapped DEK (32+16) | nonce(12) | ciphertext.
type Envelope struct{ kek cipher.AEAD }

// NewEnvelope requires a 32-byte KEK.
func NewEnvelope(kek []byte) (*Envelope, error) {
	if len(kek) != 32 {
		return nil, errors.New("crypto: KEK must be 32 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Envelope{kek: g}, nil
}

// Encrypt seals plaintext bound to associated data (e.g. "user:<id>").
func (e *Envelope) Encrypt(plaintext, ad []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(randReader, dek); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n1 := make([]byte, e.kek.NonceSize())
	n2 := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(randReader, n1); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(randReader, n2); err != nil {
		return nil, err
	}
	out := append([]byte{}, n1...)
	out = append(out, e.kek.Seal(nil, n1, dek, ad)...)
	out = append(out, n2...)
	return append(out, g.Seal(nil, n2, plaintext, ad)...), nil
}

// Decrypt opens a value produced by Encrypt with the same associated data.
func (e *Envelope) Decrypt(blob, ad []byte) ([]byte, error) {
	ns := e.kek.NonceSize()
	wrapLen := 32 + e.kek.Overhead()
	if len(blob) < ns+wrapLen+ns+16 {
		return nil, errors.New("crypto: ciphertext too short")
	}
	dek, err := e.kek.Open(nil, blob[:ns], blob[ns:ns+wrapLen], ad)
	if err != nil {
		return nil, errors.New("crypto: unwrap failed")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	rest := blob[ns+wrapLen:]
	pt, err := g.Open(nil, rest[:ns], rest[ns:], ad)
	if err != nil {
		return nil, errors.New("crypto: open failed")
	}
	return pt, nil
}
