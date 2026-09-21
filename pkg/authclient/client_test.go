package authclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const iss = "https://auth.example.org"

type signer struct {
	kid  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(kid string) signer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return signer{kid, pub, priv}
}

func (s signer) mint(now time.Time, sub, tid, sid string, life time.Duration, aud string) string {
	c := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: iss, Subject: sub, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(life)), ID: "j-" + strconv.FormatInt(now.UnixNano(), 36)}, TenantID: tid, SessionID: sid, Roles: []string{"admin"}, AMR: []string{"pwd"}}
	if aud != "" {
		c.Audience = jwt.ClaimStrings{aud}
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	t.Header["kid"] = s.kid
	out, _ := t.SignedString(s.priv)
	return out
}

type keySrc struct {
	mu    sync.Mutex
	set   map[string]ed25519.PublicKey
	calls int
	fail  bool
}

func (k *keySrc) Keys(context.Context) (map[string]ed25519.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.fail {
		return nil, errors.New("down")
	}
	out := map[string]ed25519.PublicKey{}
	for kid, pub := range k.set {
		out[kid] = pub
	}
	return out, nil
}

type revSrc struct {
	mu      sync.Mutex
	entries []Revocation
	fail    bool
}

func (r *revSrc) Since(_ context.Context, cursor string) ([]Revocation, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return nil, cursor, errors.New("feed down")
	}
	from := 0
	if cursor != "" {
		from, _ = strconv.Atoi(cursor)
	}
	if from > len(r.entries) {
		from = len(r.entries)
	}
	return append([]Revocation(nil), r.entries[from:]...), strconv.Itoa(len(r.entries)), nil
}

func (r *revSrc) set(entries ...Revocation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = entries
}

func TestOfflineVerifyAndSkew(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	s := newSigner("k1")
	ks := &keySrc{set: map[string]ed25519.PublicKey{"k1": s.pub}}
	v := New(Config{Issuer: iss, Audience: "app"}, ks, nil)
	v.now = func() time.Time { return now }
	if err := v.RefreshKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok := s.mint(now, "u1", "t1", "s1", 15*time.Minute, "app")
	id, err := v.Verify(context.Background(), tok)
	if err != nil || id.UserID != "u1" || id.TenantID != "t1" || id.SessionID != "s1" || id.Audience != "app" || id.Roles[0] != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
	if _, err := v.Verify(context.Background(), s.mint(now, "u1", "t1", "s1", 15*time.Minute, "other")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("audience mismatch accepted")
	}
	now = now.Add(15*time.Minute + 59*time.Second)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("within skew: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired accepted")
	}
	if _, err := v.Verify(context.Background(), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("empty accepted")
	}
	pinned := New(Config{Issuer: iss, TenantID: "t2"}, ks, nil)
	pinned.now = v.now
	_ = pinned.RefreshKeys(context.Background())
	now = now.Add(-10 * time.Minute)
	if _, err := pinned.Verify(context.Background(), tok); !errors.Is(err, ErrWrongTenant) {
		t.Fatalf("tenant pin: %v", err)
	}
}

func TestUnknownKidRefreshIsRateCapped(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	s1, s2 := newSigner("k1"), newSigner("k2")
	ks := &keySrc{set: map[string]ed25519.PublicKey{"k1": s1.pub}}
	v := New(Config{Issuer: iss}, ks, nil)
	v.now = func() time.Time { return now }
	_ = v.RefreshKeys(context.Background())
	tok2 := s2.mint(now, "u1", "t1", "s1", time.Minute, "")
	if _, err := v.Verify(context.Background(), tok2); err == nil {
		t.Fatal("unknown kid accepted")
	}
	calls := ks.calls
	// Rotation happened on the server; the next unknown kid within the cap
	// must not trigger another fetch.
	ks.mu.Lock()
	ks.set["k2"] = s2.pub
	ks.mu.Unlock()
	now = now.Add(10 * time.Second)
	if _, err := v.Verify(context.Background(), tok2); err == nil || ks.calls != calls {
		t.Fatalf("refresh not capped: err=%v calls=%d", err, ks.calls)
	}
	now = now.Add(time.Minute)
	if _, err := v.Verify(context.Background(), tok2); err != nil || ks.calls != calls+1 {
		t.Fatalf("refresh after cap: %v calls=%d", err, ks.calls)
	}
}

func TestRevocationFeedAndFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	s := newSigner("k1")
	ks := &keySrc{set: map[string]ed25519.PublicKey{"k1": s.pub}}
	rs := &revSrc{}
	v := New(Config{Issuer: iss, MaxStale: 60 * time.Minute}, ks, rs)
	v.now = func() time.Time { return now }
	_ = v.RefreshKeys(context.Background())
	tok := s.mint(now, "u1", "t1", "s1", 15*time.Minute, "")
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrStale) {
		t.Fatalf("never synced must fail closed: %v", err)
	}
	if err := v.SyncRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	// Entries before iat do not apply; entries at/after iat do, per kind.
	rs.set(Revocation{TS: now.Add(-time.Minute), Kind: "session", SubjectID: "s1"})
	_ = v.SyncRevocations(context.Background())
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal("older entry must not revoke")
	}
	for _, e := range []Revocation{{TS: now, Kind: "session", SubjectID: "s1"}, {TS: now.Add(time.Second), Kind: "user", SubjectID: "u1", TenantID: "t1"}, {TS: now.Add(time.Second), Kind: "tenant", SubjectID: "t1"}} {
		rs.set(e)
		v.mu.Lock()
		v.entries, v.cursor = nil, ""
		v.mu.Unlock()
		_ = v.SyncRevocations(context.Background())
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrRevoked) {
			t.Fatalf("%s entry must revoke: %v", e.Kind, err)
		}
	}
	other := s.mint(now, "u2", "t2", "s2", 15*time.Minute, "")
	if _, err := v.Verify(context.Background(), other); err != nil {
		t.Fatal("unrelated token affected")
	}
	// A feed that has been unreachable for longer than MaxStale fails closed.
	rs.mu.Lock()
	rs.fail = true
	rs.mu.Unlock()
	now = now.Add(61 * time.Minute)
	_ = v.SyncRevocations(context.Background())
	fresh := s.mint(now, "u2", "t2", "s2", 15*time.Minute, "")
	if _, err := v.Verify(context.Background(), fresh); !errors.Is(err, ErrStale) {
		t.Fatalf("stale feed must fail closed: %v", err)
	}
	rs.mu.Lock()
	rs.fail = false
	rs.mu.Unlock()
	if err := v.SyncRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	// Start runs the loops and stops with the context.
	ctx, cancel := context.WithCancel(context.Background())
	if err := v.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	ks.mu.Lock()
	ks.fail = true
	ks.mu.Unlock()
	if err := New(Config{Issuer: iss}, ks, rs).Start(context.Background(), nil); err == nil {
		t.Fatal("start must fail fast on key errors")
	}
}

func TestMiddlewareAndInterceptor(t *testing.T) {
	now := time.Now()
	s := newSigner("k1")
	v := New(Config{Issuer: iss}, StaticKeys{"k1": s.pub}, nil)
	_ = v.RefreshKeys(context.Background())
	tok := s.mint(now, "u1", "t1", "s1", 5*time.Minute, "")
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := FromContext(r.Context())
		_, _ = w.Write([]byte(id.UserID))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "u1" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	ic := UnaryInterceptor(v)
	next := func(ctx context.Context, _ any) (any, error) { id, _ := FromContext(ctx); return id.UserID, nil }
	if _, err := ic(context.Background(), nil, &grpc.UnaryServerInfo{}, next); err == nil {
		t.Fatal("missing metadata accepted")
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	if out, err := ic(ctx, nil, &grpc.UnaryServerInfo{}, next); err != nil || out != "u1" {
		t.Fatal(out, err)
	}
	// JWKS over HTTPS (httptest TLS server) and the https-only rule.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + NewJWK("k1", s.pub, "active").X + `","use":"sig","alg":"EdDSA"}]}`))
	}))
	defer srv.Close()
	keys, err := HTTPKeys{URL: srv.URL + "/.well-known/jwks.json", Client: srv.Client()}.Keys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	if _, err := (HTTPKeys{URL: "http://plain/jwks"}).Keys(context.Background()); err == nil {
		t.Fatal("plaintext jwks accepted")
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"RSA","kid":"r"}]}`)); err == nil {
		t.Fatal("non-Ed25519 key accepted")
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"},{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"}]}`)); err == nil {
		t.Fatal("malformed/duplicate accepted")
	}
}
