package token

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

// Claims are the access-token claims (contracts/token.md); shared with verifiers.
type Claims = authclient.Claims

// ErrBrokenKey means the active key has no usable private half.
var ErrBrokenKey = errors.New("token: active key unusable")

// Issuer mints and verifies tokens with the ring.
type Issuer struct {
	Ring   *Ring
	Issuer string // iss
	now    func() time.Time
}

// NewIssuer binds the ring to an issuer URL.
func NewIssuer(r *Ring, iss string) *Issuer { return &Issuer{Ring: r, Issuer: iss, now: time.Now} }

// Request describes a token to mint.
type Request struct {
	UserID, TenantID, SessionID string
	Roles, AMR                  []string
	Audience                    string        // client id for the OAuth flow
	Lifetime                    time.Duration // ≤ ring AccessLifetime; 0 = ring default
}

// Issue signs a token with the active key.
func (i *Issuer) Issue(req Request) (string, Claims, error) {
	k, err := i.Ring.active()
	if err != nil {
		return "", Claims{}, err
	}
	life := req.Lifetime
	if life <= 0 || life > i.Ring.cfg.AccessLifetime {
		life = i.Ring.cfg.AccessLifetime
	}
	if req.UserID == "" || req.TenantID == "" || req.SessionID == "" {
		return "", Claims{}, errors.New("token: user, tenant and session are required")
	}
	now := i.now()
	c := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: i.Issuer, Subject: req.UserID, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(life)), ID: store.NewID()}, TenantID: req.TenantID, SessionID: req.SessionID, Roles: nonNil(req.Roles), AMR: nonNil(req.AMR)}
	if req.Audience != "" {
		c.Audience = jwt.ClaimStrings{req.Audience}
	}
	if k.priv == nil {
		return "", Claims{}, ErrBrokenKey
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = k.KID
	s, err := tok.SignedString(k.priv)
	if err != nil {
		return "", Claims{}, err
	}
	return s, c, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Verify parses and validates a token against the ring (alg pinned to
// EdDSA, kid required, issuer and time checks with the configured skew).
func (i *Issuer) Verify(s string) (Claims, error) {
	return Verify(s, i.Issuer, i.Ring.cfg.ClockSkew, i.Ring.cfg.AccessLifetime, i.now, func(kid string) (ed25519.PublicKey, bool) { return i.Ring.PublicKey(kid) })
}

// Verify is the shared validation used by the issuer and by tests.
func Verify(s, iss string, skew, maxLife time.Duration, now func() time.Time, lookup func(kid string) (ed25519.PublicKey, bool)) (Claims, error) {
	return authclient.VerifyToken(s, iss, skew, maxLife, now, lookup)
}
