package authclient

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the access-token claims (contracts/token.md). No PII.
type Claims struct {
	jwt.RegisteredClaims
	TenantID  string   `json:"tid"`
	SessionID string   `json:"sid"`
	Roles     []string `json:"roles"`
	AMR       []string `json:"amr"`
}

// MaxTokenLifetime is the contract ceiling for exp − iat.
const MaxTokenLifetime = 15 * time.Minute

// VerifyToken parses and validates a token: alg pinned to EdDSA, kid required
// and known, signature valid, issuer matches, times within skew, lifetime
// within maxLife and every required claim present.
func VerifyToken(s, iss string, skew, maxLife time.Duration, now func() time.Time, lookup func(kid string) (ed25519.PublicKey, bool)) (Claims, error) {
	if len(s) > 8<<10 {
		return Claims{}, errors.New("token: too long")
	}
	if skew < 0 || skew > 60*time.Second {
		skew = 60 * time.Second
	}
	if maxLife <= 0 || maxLife > MaxTokenLifetime {
		maxLife = MaxTokenLifetime
	}
	if now == nil {
		now = time.Now
	}
	var c Claims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithIssuer(iss), jwt.WithLeeway(skew),
		jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithTimeFunc(now))
	_, err := parser.ParseWithClaims(s, &c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, errors.New("alg must be EdDSA")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid required")
		}
		pub, ok := lookup(kid)
		if !ok {
			return nil, &UnknownKeyError{Kid: kid}
		}
		return pub, nil
	})
	if err != nil {
		var uk *UnknownKeyError
		if errors.As(err, &uk) {
			return Claims{}, uk
		}
		return Claims{}, fmt.Errorf("token: %w", err)
	}
	if c.IssuedAt == nil || c.ExpiresAt == nil || c.NotBefore == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > maxLife {
		return Claims{}, errors.New("token: lifetime exceeds the maximum")
	}
	if c.Subject == "" || c.TenantID == "" || c.SessionID == "" || c.ID == "" {
		return Claims{}, errors.New("token: required claims missing")
	}
	return c, nil
}

// UnknownKeyError signals a kid outside the current key set (a refresh may fix it).
type UnknownKeyError struct{ Kid string }

func (e *UnknownKeyError) Error() string { return fmt.Sprintf("token: unknown kid %q", e.Kid) }
