package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// EnrollAudience is the fixed audience of an lcm enrollment (join) token.
const EnrollAudience = "lcm"

// maxEnrollLifetime caps an enrollment token's lifetime; the default is shorter.
const (
	maxEnrollLifetime     = 30 * time.Minute
	defaultEnrollLifetime = 10 * time.Minute
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
// spiffePaths under tenantID, valid for ttl (clamped to maxEnrollLifetime).
func (i *Issuer) IssueEnrollment(tenantID string, spiffePaths []string, ttl time.Duration) (string, EnrollGrant, error) {
	if tenantID == "" || len(spiffePaths) == 0 {
		return "", EnrollGrant{}, errors.New("token: tenant and spiffe paths are required")
	}
	if ttl <= 0 || ttl > maxEnrollLifetime {
		ttl = defaultEnrollLifetime
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
		return EnrollGrant{}, fmt.Errorf("token: %w", err)
	}
	if c.ExpiresAt == nil || c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > maxEnrollLifetime {
		return EnrollGrant{}, errors.New("token: lifetime exceeds the maximum")
	}
	if c.TenantID == "" || c.ID == "" || len(c.SpiffePaths) == 0 {
		return EnrollGrant{}, errors.New("token: required claims missing")
	}
	return EnrollGrant{JTI: c.ID, TenantID: c.TenantID, SpiffePaths: c.SpiffePaths, ExpiresAt: c.ExpiresAt.Time}, nil
}
