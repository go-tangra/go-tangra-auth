package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"time"
)

// ConstantTimeEqual compares strings without leaking their contents through timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RandomToken returns n random bytes, base64url-encoded (invitations, recovery, sessions).
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex SHA-256 of a token: what the database stores.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// PadTo sleeps until at least d has elapsed since start, so enumeration-
// sensitive flows respond in constant time regardless of the branch taken.
func PadTo(start time.Time, d time.Duration) {
	if rem := d - time.Since(start); rem > 0 {
		time.Sleep(rem)
	}
}

// randReader is crypto/rand unless a test injected a failing source.
var randReader io.Reader = rand.Reader

// Rand returns the randomness source used by this package and by key
// generation elsewhere in the service.
func Rand() io.Reader { return randReader }

// SetRand replaces the randomness source and returns a restore function.
// It exists so tests can exercise "randomness unavailable" branches; it must
// never be called outside tests.
func SetRand(r io.Reader) (restore func()) {
	prev := randReader
	randReader = r
	return func() { randReader = prev }
}
