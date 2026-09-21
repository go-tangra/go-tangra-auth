// Package password applies the tenant password policy and verifies
// credentials with enumeration-safe timing.
package password

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/tenant"
)

// MaxLength bounds passwords (argon2 cost is linear in length).
const MaxLength = 1024

// PadDuration is the floor every credential check takes, so callers cannot
// distinguish "no such account" from "wrong password" (SR-007, SC-006).
const PadDuration = 300 * time.Millisecond

// Policy errors (reason "password_policy" at the API).
var (
	ErrTooShort = errors.New("password: shorter than the tenant minimum")
	ErrTooLong  = errors.New("password: longer than 1024 characters")
	ErrWeak     = errors.New("password: must not be blank or a single repeated character")
)

// Check applies the tenant policy to a new password.
func Check(p tenant.Policy, pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n > MaxLength:
		return ErrTooLong
	case n < p.PasswordMinLength:
		return ErrTooShort
	case strings.TrimSpace(pw) == "" || strings.Count(pw, pw[:1]) == len(pw):
		return ErrWeak
	}
	return nil
}

// Hash produces an argon2id PHC string with the current parameters.
func Hash(pw string) (string, error) { return crypto.HashPassword(pw, crypto.DefaultParams) }

// dummyHash is verified when the account does not exist so the work factor
// is identical on both paths.
var dummyHash = func() string {
	h, err := crypto.HashPassword("freya-dummy-password", crypto.DefaultParams)
	if err != nil {
		panic(err)
	}
	return h
}()

// Verify checks pw against encoded. An empty encoded (unknown or invited
// account) still performs a full hash and always returns false.
func Verify(pw string, encoded string) (ok, rehash bool) {
	if utf8.RuneCountInString(pw) > MaxLength {
		pw = pw[:MaxLength]
	}
	if encoded == "" {
		_, _, _ = crypto.VerifyPassword(pw, dummyHash)
		return false, false
	}
	ok, rehash, err := crypto.VerifyPassword(pw, encoded)
	if err != nil {
		return false, false
	}
	return ok, rehash
}

// Pad sleeps until PadDuration has elapsed since start.
func Pad(start time.Time) { crypto.PadTo(start, PadDuration) }
