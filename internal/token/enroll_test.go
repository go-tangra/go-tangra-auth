package token

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/store"
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

	// Required inputs; an out-of-range ttl falls back to the default lifetime.
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
		"long lifetime":  sign(claims(time.Hour, "t1"), kid),
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
