package token

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

func TestIssueVerifyEnrollment(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now

	tok, grant, err := iss.IssueEnrollment("t1", []string{"svc/notification"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if grant.JTI == "" || grant.TenantID != "t1" || grant.SpiffePaths[0] != "svc/notification" {
		t.Fatalf("grant %+v", grant)
	}
	got, err := iss.VerifyEnrollment(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JTI != grant.JTI || got.TenantID != "t1" || got.SpiffePaths[0] != "svc/notification" {
		t.Fatalf("verified %+v", got)
	}

	// wrong audience: an access token must not verify as an enrollment token.
	access, _, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1", Audience: "app"})
	if _, err := iss.VerifyEnrollment(access); err == nil {
		t.Fatal("access token accepted as enrollment token")
	}

	// expired.
	past := now.Add(-time.Hour)
	iss2 := NewIssuer(r, "https://auth.example.org")
	iss2.now = func() time.Time { return past }
	old, _, _ := iss2.IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	if _, err := iss.VerifyEnrollment(old); err == nil {
		t.Fatal("expired enrollment token accepted")
	}
}

func TestEnrollmentFailures(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now

	// Required inputs; ttl <= 0 means the default lifetime.
	if _, _, err := iss.IssueEnrollment("", []string{"svc/x"}, time.Minute); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if _, _, err := iss.IssueEnrollment("t1", nil, time.Minute); err == nil {
		t.Fatal("empty spiffe paths accepted")
	}
	_, g, err := iss.IssueEnrollment("t1", []string{"svc/x"}, 0)
	if err != nil || !g.ExpiresAt.Equal(now.Add(defaultEnrollLifetime)) {
		t.Fatalf("default ttl: %v %v", g.ExpiresAt, err)
	}

	// Oversized input and an out-of-range configured skew.
	if _, err := iss.VerifyEnrollment(strings.Repeat("a", 8<<10+1)); err == nil {
		t.Fatal("oversized token accepted")
	}
	r.cfg.ClockSkew = -time.Second
	tok, _, _ := iss.IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	if _, err := iss.VerifyEnrollment(tok); err != nil {
		t.Fatalf("clamped skew: %v", err)
	}

	// Hand-signed tokens: no kid, unknown kid, over-long lifetime, missing claims.
	kid := r.Keys()[0].KID
	priv := r.keys[kid].priv
	sign := func(c EnrollClaims, kid string) string {
		tk := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		if kid != "" {
			tk.Header["kid"] = kid
		}
		s, err := tk.SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	claims := func(ttl time.Duration, tid string) EnrollClaims {
		return EnrollClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: iss.Issuer, Subject: tid, Audience: jwt.ClaimStrings{EnrollAudience},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)), ID: "j"},
			TenantID: tid, SpiffePaths: []string{"svc/x"}}
	}
	for name, s := range map[string]string{
		"no kid":         sign(claims(time.Minute, "t1"), ""),
		"unknown kid":    sign(claims(time.Minute, "t1"), "nope"),
		"long lifetime":  sign(claims(maxEnrollLifetime+time.Second, "t1"), kid),
		"missing tenant": sign(claims(time.Minute, ""), kid),
	} {
		if _, err := iss.VerifyEnrollment(s); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// A broken key, a non-Ed25519 signer and an empty ring cannot issue.
	pub, _, _ := ed25519.GenerateKey(nil)
	r.mu.Lock()
	r.keys = map[string]*ringKey{"broken": {SigningKey: store.SigningKey{KID: "broken", PublicKey: pub, State: StateActive, CreatedAt: now}, priv: nil}}
	r.mu.Unlock()
	if _, _, err := iss.IssueEnrollment("t1", []string{"svc/x"}, time.Minute); !errors.Is(err, ErrBrokenKey) {
		t.Fatalf("broken key: %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(crypto.Rand(), 2048)
	r.mu.Lock()
	r.keys = map[string]*ringKey{"rsa": {SigningKey: store.SigningKey{KID: "rsa", PublicKey: pub, State: StateActive, CreatedAt: now}, priv: rsaKey}}
	r.mu.Unlock()
	if _, _, err := iss.IssueEnrollment("t1", []string{"svc/x"}, time.Minute); err == nil || errors.Is(err, ErrBrokenKey) {
		t.Fatalf("foreign signer: %v", err)
	}
	r.mu.Lock()
	r.keys = map[string]*ringKey{}
	r.mu.Unlock()
	if _, _, err := iss.IssueEnrollment("t1", []string{"svc/x"}, time.Minute); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("empty ring: %v", err)
	}
}

// The lifetime is up to 24 h (the gateway's add-module join tokens); a longer
// one is refused, never silently shortened; 0 or negative means the default.
func TestEnrollmentLifetimeBounds(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now

	if maxEnrollLifetime != 24*time.Hour || defaultEnrollLifetime != 10*time.Minute {
		t.Fatalf("bounds: max %v default %v", maxEnrollLifetime, defaultEnrollLifetime)
	}
	tok, g, err := iss.IssueEnrollment("t1", []string{"svc/x"}, 24*time.Hour)
	if err != nil || !g.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("24h: %v %v", g.ExpiresAt, err)
	}
	// It verifies until the end of its life.
	now = now.Add(24*time.Hour - time.Minute)
	if got, err := iss.VerifyEnrollment(tok); err != nil || got.JTI != g.JTI {
		t.Fatalf("24h token near its end: %v", err)
	}
	now = now.Add(-(24*time.Hour - time.Minute))

	for _, ttl := range []time.Duration{24*time.Hour + time.Second, 48 * time.Hour} {
		s, _, err := iss.IssueEnrollment("t1", []string{"svc/x"}, ttl)
		if !errors.Is(err, ErrEnrollmentLifetime) || s != "" {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		_, g, err := iss.IssueEnrollment("t1", []string{"svc/x"}, ttl)
		if err != nil || !g.ExpiresAt.Equal(now.Add(10*time.Minute)) {
			t.Fatalf("ttl %v: %v %v", ttl, g.ExpiresAt, err)
		}
	}
}

// A 24 h enrollment token minted just before a rotation stays verifiable for
// its whole life: the retired key is kept until it could no longer matter.
func TestEnrollmentSurvivesRotation(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now) // rotation every hour, retiring 10 min
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now
	first := r.Keys()[0].KID
	now = now.Add(59 * time.Minute)
	tok, _, err := iss.IssueEnrollment("t1", []string{"svc/x"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	minted := now
	for now.Before(minted.Add(24*time.Hour - time.Minute)) {
		now = now.Add(5 * time.Minute)
		if err := r.Sweep(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := iss.VerifyEnrollment(tok); err != nil {
		t.Fatalf("24h token after rotations: %v", err)
	}
	// Removed once its last token has expired (plus skew).
	for now.Before(minted.Add(26 * time.Hour)) {
		now = now.Add(5 * time.Minute)
		_ = r.Sweep(t.Context())
	}
	if _, ok := r.PublicKey(first); ok {
		t.Fatal("retired key kept forever")
	}
}

func TestVerifyEnrollmentRefusalKinds(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now
	at := func(ts time.Time) *Issuer {
		i := NewIssuer(r, "https://auth.example.org")
		i.now = func() time.Time { return ts }
		return i
	}

	// Expired: minted an hour ago with a one-minute lifetime.
	old, _, _ := at(now.Add(-time.Hour)).IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	if _, err := iss.VerifyEnrollment(old); !errors.Is(err, ErrEnrollmentExpired) || errors.Is(err, ErrEnrollmentNotYetValid) {
		t.Fatalf("expired: %v", err)
	}
	// Not yet valid: minted (nbf, iat) beyond the clock skew in the future.
	future, _, _ := at(now.Add(time.Hour)).IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	if _, err := iss.VerifyEnrollment(future); !errors.Is(err, ErrEnrollmentNotYetValid) || errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("not yet valid: %v", err)
	}

	// Opaque: an expired token from a different issuer, an expired access token
	// (wrong audience), a forged signature and garbage never name the window.
	other := NewIssuer(r, "https://other.example.org")
	other.now = func() time.Time { return now.Add(-time.Hour) }
	foreign, _, _ := other.IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	oldIss := at(now.Add(-time.Hour))
	access, _, _ := oldIss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1", Audience: "app"})
	good, _, _ := iss.IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	forged := good[:len(good)-4] + "AAAA"
	if forged == good {
		forged = good[:len(good)-4] + "BBBB"
	}
	for name, s := range map[string]string{"foreign issuer": foreign, "access token": access, "forged": forged, "garbage": "not.a.jwt"} {
		_, err := iss.VerifyEnrollment(s)
		if err == nil || errors.Is(err, ErrEnrollmentExpired) || errors.Is(err, ErrEnrollmentNotYetValid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
