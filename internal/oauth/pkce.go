// Package oauth implements the OAuth 2.1 authorization-code flow subset used
// by first-party applications: PKCE S256 only, exact redirect URI matching,
// one-time short-lived codes, no implicit or password grants.
package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE limits (RFC 7636).
const (
	MinVerifier = 43
	MaxVerifier = 128
)

// ErrPKCE is returned for malformed or mismatching verifiers.
var ErrPKCE = errors.New("oauth: pkce verification failed")

func validVerifier(v string) bool {
	if len(v) < MinVerifier || len(v) > MaxVerifier {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// Challenge computes the S256 challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks verifier against the challenge sent at /authorize.
func VerifyPKCE(verifier, challenge string) error {
	if !validVerifier(verifier) || challenge == "" {
		return ErrPKCE
	}
	if subtle.ConstantTimeCompare([]byte(Challenge(verifier)), []byte(challenge)) != 1 {
		return ErrPKCE
	}
	return nil
}
