package token

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
)

func newRing(t *testing.T, now *time.Time) (*Ring, *MemKeys) {
	t.Helper()
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	ks := NewMemKeys()
	r := NewRing(ks, env, Config{AccessLifetime: 15 * time.Minute, RotationInterval: time.Hour, RetiringPeriod: 10 * time.Minute, ClockSkew: 60 * time.Second})
	r.now = func() time.Time { return *now }
	if err := r.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	return r, ks
}

func TestIssueVerifyAndClaims(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now
	s, c, err := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1", Roles: []string{"admin"}, AMR: []string{"pwd", "otp"}, Audience: "app1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAt.Sub(c.IssuedAt.Time) != 15*time.Minute || c.ID == "" || c.Audience[0] != "app1" {
		t.Fatalf("claims %+v", c)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(s, ".")[0])
	if !strings.Contains(string(hdr), `"alg":"EdDSA"`) || !strings.Contains(string(hdr), `"kid":"`) {
		t.Fatalf("header %s", hdr)
	}
	body, _ := base64.RawURLEncoding.DecodeString(strings.Split(s, ".")[1])
	for _, pii := range []string{"email", "name"} {
		if strings.Contains(string(body), `"`+pii+`"`) {
			t.Fatalf("PII in token: %s", body)
		}
	}
	got, err := iss.Verify(s)
	if err != nil || got.Subject != "u1" || got.TenantID != "t1" || got.SessionID != "s1" || got.Roles[0] != "admin" || len(got.AMR) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	// Lifetime is capped at the ring maximum; roles/amr never null.
	_, c2, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1", Lifetime: time.Hour})
	if c2.ExpiresAt.Sub(c2.IssuedAt.Time) != 15*time.Minute {
		t.Fatal("lifetime cap")
	}
	if b, _ := json.Marshal(c2); !strings.Contains(string(b), `"roles":[]`) {
		t.Fatalf("%s", b)
	}
	if _, _, err := iss.Issue(Request{UserID: "u1"}); err == nil {
		t.Fatal("missing tenant/session accepted")
	}
	// Expiry and skew.
	now = now.Add(15*time.Minute + 30*time.Second)
	if _, err := iss.Verify(s); err != nil {
		t.Fatalf("within skew: %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := iss.Verify(s); err == nil {
		t.Fatal("expired accepted")
	}
	now = now.Add(-time.Hour)
	if _, err := iss.Verify(s); err == nil {
		t.Fatal("not-yet-valid accepted")
	}
}

func TestVerifyRefusesAlgConfusionAndForeignKeys(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now
	good, _, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1"})
	kid := r.Keys()[0].KID
	pub, _ := r.PublicKey(kid)
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: iss.Issuer, Subject: "u1", IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), ID: "j"}, TenantID: "t1", SessionID: "s1"}
	// HS256 signed with the public key bytes ("alg confusion").
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hs.Header["kid"] = kid
	forged, _ := hs.SignedString([]byte(pub))
	if _, err := iss.Verify(forged); err == nil {
		t.Fatal("HS256 accepted")
	}
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	none.Header["kid"] = kid
	unsigned, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := iss.Verify(unsigned); err == nil {
		t.Fatal("none accepted")
	}
	// A valid EdDSA signature from a key outside the ring.
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	ft := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	ft.Header["kid"] = "foreign"
	fs, _ := ft.SignedString(foreign)
	if _, err := iss.Verify(fs); err == nil {
		t.Fatal("foreign kid accepted")
	}
	ft.Header["kid"] = kid
	fs, _ = ft.SignedString(foreign)
	if _, err := iss.Verify(fs); err == nil {
		t.Fatal("bad signature accepted")
	}
	// No kid, wrong issuer, over-long lifetime, tampered payload.
	nk := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if s, _ := nk.SignedString(foreign); s != "" {
		if _, err := iss.Verify(s); err == nil {
			t.Fatal("missing kid accepted")
		}
	}
	other := NewIssuer(r, "https://evil.example.org")
	other.now = r.now
	if _, err := other.Verify(good); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
	long := claims
	long.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Hour))
	lt := jwt.NewWithClaims(jwt.SigningMethodEdDSA, long)
	lt.Header["kid"] = kid
	ls, _ := lt.SignedString(r.keys[kid].priv)
	if _, err := iss.Verify(ls); err == nil {
		t.Fatal("2h lifetime accepted")
	}
	parts := strings.Split(good, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.example.org","sub":"u2"}`))
	if _, err := iss.Verify(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered accepted")
	}
	if _, err := iss.Verify("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestRotationStatesAndJWKS(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	r, ks := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now
	first := r.Keys()[0].KID
	// A token minted just before rotation must stay verifiable afterwards.
	now = now.Add(59 * time.Minute)
	tok1, _, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1"})
	now = now.Add(2 * time.Minute)
	if err := r.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, k := range r.Keys() {
		states[k.KID] = k.State
	}
	if states[first] != StateRetiring || len(states) != 2 {
		t.Fatalf("after rotation: %v", states)
	}
	tok2, _, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1"})
	tok2At := now
	if hdr := strings.Split(tok2, ".")[0]; strings.Contains(hdr, first) {
		t.Fatal("retiring key must not sign")
	}
	set := r.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("jwks %v", set)
	}
	keys, err := authclient.ParseJWKS(r.JWKSJSON())
	if err != nil || len(keys) != 2 {
		t.Fatal(err)
	}
	if bytes.Contains(r.JWKSJSON(), []byte(`"d"`)) {
		t.Fatal("private material exported")
	}
	// Old token still verifies while its key is retiring/retired.
	if _, err := iss.Verify(tok1); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	_ = r.Sweep(t.Context())
	for _, k := range r.Keys() {
		if k.KID == first && k.State != StateRetired {
			t.Fatalf("expected retired, got %s", k.State)
		}
	}
	if _, ok := r.PublicKey(first); !ok {
		t.Fatal("retired key must stay published")
	}
	// Forgotten only after the last possible token expired (15m + skew).
	now = now.Add(16 * time.Minute)
	_ = r.Sweep(t.Context())
	if _, ok := r.PublicKey(first); ok || ks.Len() != 1 {
		t.Fatalf("retired key still present (%d keys)", ks.Len())
	}
	// Reload from the store keeps the active key and unseals it.
	now = tok2At.Add(time.Minute)
	r2 := NewRing(ks, r.env, r.cfg)
	r2.now = r.now
	if err := r2.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	iss2 := NewIssuer(r2, iss.Issuer)
	iss2.now = r.now
	if _, err := iss2.Verify(tok2); err != nil {
		t.Fatal(err)
	}
	// Wrong KEK cannot load the ring.
	bad, _ := crypto.NewEnvelope(bytes.Repeat([]byte{9}, 32))
	if err := NewRing(ks, bad, r.cfg).Load(t.Context()); err == nil {
		t.Fatal("wrong kek loaded keys")
	}
	// Run sweeps on a ticker and stops with the context.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	r.Run(ctx, 5*time.Millisecond, nil)
}
