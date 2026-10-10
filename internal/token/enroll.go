package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// EnrollAudience is the fixed audience of an lcm enrollment (join) token.
const EnrollAudience = "lcm"

// maxEnrollLifetime caps an enrollment token's lifetime (24 h: the gateway's
// add-module join bundles are installed by an operator later in the day); a
// longer request is refused, not shortened. The default is 10 minutes. The
// ring keeps a retired signing key at least this long (see Ring.Sweep), so a
// token stays verifiable for its whole life across key rotations.
const (
	maxEnrollLifetime     = 24 * time.Hour
	defaultEnrollLifetime = 10 * time.Minute
)

// MaxEnrollLifetime is the longest lifetime IssueEnrollment accepts.
const MaxEnrollLifetime = maxEnrollLifetime

// ErrEnrollmentLifetime refuses a requested lifetime above maxEnrollLifetime.
var ErrEnrollmentLifetime = fmt.Errorf("token: enrollment token lifetime exceeds the maximum of %s", maxEnrollLifetime)

// Time-window refusals of an otherwise authentic enrollment token (good
// signature, kid, issuer and audience). VerifyEnrollment wraps them so the
// caller can tell an operator WHY a join failed; every other failure is opaque.
var (
	ErrEnrollmentExpired     = errors.New("token: enrollment token expired")
	ErrEnrollmentNotYetValid = errors.New("token: enrollment token not yet valid")
)

// EnrollClaims are the claims of an lcm enrollment token: a short-lived,
// single-use, service-to-service credential authorising ONE SVID enrollment for
// a bounded set of SPIFFE paths. It carries no user/session (unlike access
// tokens), so it has its own issue/verify rather than reusing Issue/Verify.
type EnrollClaims struct {
	jwt.RegisteredClaims
	TenantID    string   `json:"tid"`
	SpiffePaths []string `json:"spiffe_paths"`
}

// EnrollGrant is the verified content of an enrollment token. Single-use is
// enforced separately by burning JTI via store.ConsumeEnrollmentJTI.
type EnrollGrant struct {
	JTI         string
	TenantID    string
	SpiffePaths []string
	ExpiresAt   time.Time
}

// IssueEnrollment signs a single-use enrollment token authorising enrollment of
// spiffePaths under tenantID, valid for ttl: ttl <= 0 means the default (10
// min); a ttl above maxEnrollLifetime (24 h) is refused with
// ErrEnrollmentLifetime.
func (i *Issuer) IssueEnrollment(tenantID string, spiffePaths []string, ttl time.Duration) (string, EnrollGrant, error) {
	if tenantID == "" || len(spiffePaths) == 0 {
		return "", EnrollGrant{}, errors.New("token: tenant and spiffe paths are required")
	}
	switch {
	case ttl <= 0:
		ttl = defaultEnrollLifetime
	case ttl > maxEnrollLifetime:
		return "", EnrollGrant{}, ErrEnrollmentLifetime
	}
	k, err := i.Ring.active()
	if err != nil {
		return "", EnrollGrant{}, err
	}
	if k.priv == nil {
		return "", EnrollGrant{}, ErrBrokenKey
	}
	now := i.now()
	jti := store.NewID()
	exp := now.Add(ttl)
	c := EnrollClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: i.Issuer, Subject: tenantID, Audience: jwt.ClaimStrings{EnrollAudience},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(exp), ID: jti,
		},
		TenantID: tenantID, SpiffePaths: spiffePaths,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = k.KID
	s, err := tok.SignedString(k.priv)
	if err != nil {
		return "", EnrollGrant{}, err
	}
	return s, EnrollGrant{JTI: jti, TenantID: tenantID, SpiffePaths: spiffePaths, ExpiresAt: exp}, nil
}

// VerifyEnrollment validates an enrollment token (EdDSA, kid, issuer, audience
// "lcm", times) and returns its grant. It does NOT enforce single-use; the
// caller burns the JTI via store.ConsumeEnrollmentJTI.
func (i *Issuer) VerifyEnrollment(s string) (EnrollGrant, error) {
	if len(s) > 8<<10 {
		return EnrollGrant{}, errors.New("token: too long")
	}
	skew := i.Ring.cfg.ClockSkew
	if skew < 0 || skew > 60*time.Second {
		skew = 60 * time.Second
	}
	var c EnrollClaims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}), jwt.WithIssuer(i.Issuer),
		jwt.WithAudience(EnrollAudience), jwt.WithLeeway(skew), jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithTimeFunc(i.now))
	// WithValidMethods rejects every non-EdDSA alg before the key func runs.
	_, err := parser.ParseWithClaims(s, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid required")
		}
		pub, ok := i.Ring.PublicKey(kid)
		if !ok {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	})
	if err != nil {
		return EnrollGrant{}, enrollParseError(err)
	}
	if c.ExpiresAt == nil || c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > maxEnrollLifetime {
		return EnrollGrant{}, errors.New("token: lifetime exceeds the maximum")
	}
	if c.TenantID == "" || c.ID == "" || len(c.SpiffePaths) == 0 {
		return EnrollGrant{}, errors.New("token: required claims missing")
	}
	return EnrollGrant{JTI: c.ID, TenantID: c.TenantID, SpiffePaths: c.SpiffePaths, ExpiresAt: c.ExpiresAt.Time}, nil
}

// enrollParseError names a time-window failure only when it is the sole claim
// failure: the signature was already verified (jwt checks it before claims), and
// a wrong issuer or audience keeps the token opaque even if it is also expired.
func enrollParseError(err error) error {
	if !errors.Is(err, jwt.ErrTokenInvalidIssuer) && !errors.Is(err, jwt.ErrTokenInvalidAudience) {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return fmt.Errorf("%w: %w", ErrEnrollmentExpired, err)
		case errors.Is(err, jwt.ErrTokenNotValidYet), errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
			return fmt.Errorf("%w: %w", ErrEnrollmentNotYetValid, err)
		}
	}
	return fmt.Errorf("token: %w", err)
}
