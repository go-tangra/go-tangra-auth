package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type profiles struct{ ms *memstore.Store }

func (p profiles) Profile(ctx context.Context, tenantID, userID string) (Profile, error) {
	for _, u := range p.ms.Users {
		if u.TenantID == tenantID && u.ID == userID {
			t, _ := p.ms.Tenant(ctx, tenantID)
			pol, _ := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
			return Profile{Email: u.Email, DisplayName: u.DisplayName, FirstName: u.FirstName, LastName: u.LastName, AvatarURL: tenantctx.AvatarURL(u.ID, u.AvatarID),
				MFAEnabled: u.MFAEnabled, MFARequired: pol.MFARequired, TenantSlug: t.Slug, TenantName: t.DisplayName}, nil
		}
	}
	return Profile{}, store.ErrNotFound
}

type us1 struct {
	outbox   *email.Outbox
	srv      *Server
	ms       *memstore.Store
	ring     *token.Ring
	sessions *session.Manager
	signin   *user.Service
}

func newUS1(t *testing.T) *us1 {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", DisplayName: "Acme", Status: "active", Kind: "customer", Policy: []byte(`{"lockout_threshold":3,"lockout_duration":"5m"}`)})
	h, _ := password.Hash("correct horse battery")
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "alice@x.test", DisplayName: "Alice", Status: "active", PasswordHash: &h})
	ms.SetRoles(tid, "u1", []string{"admin"})
	c := cache.New(cache.NewMemory())
	sm := session.New(ms, c, nil)
	svc := user.New(ms, c, nil, sm, nil)
	svc.SetPad(func(time.Time) {})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{1}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	srv, err := NewHandler(rt, WithSessions(sm))
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterUS1(US1Deps{Signin: svc, Sessions: sm, Tokens: token.NewIssuer(ring, "https://auth.example.org"), Ring: ring, Tenants: ms, Profiles: profiles{ms}})
	return &us1{srv: srv, ms: ms, ring: ring, sessions: sm, signin: svc}
}

func (u *us1) call(method, path, body string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	r = r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.5"))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		r.Header.Set(edge.CSRFHeader, "double-submit-token") // the edge filter verifies it against the cookie
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	u.srv.Handler().ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	return nil
}

func TestSigninFlowAndSessions(t *testing.T) {
	u := newUS1(t)
	if w, out := u.call("GET", "/api/v1/tenants/resolve?slug=acme", ""); w.Code != 200 || out["display_name"] != "Acme" {
		t.Fatalf("%d %v", w.Code, out)
	}
	for _, slug := range []string{"nope", "Bad%20Slug", ""} {
		if w, _ := u.call("GET", "/api/v1/tenants/resolve?slug="+slug, ""); w.Code != 404 && w.Code != 400 {
			t.Fatalf("%q → %d", slug, w.Code)
		}
	}
	// Identical refusal for unknown account and wrong password.
	for _, body := range []string{`{"tenant":"acme","email":"nobody@x.test","password":"correct horse battery"}`, `{"tenant":"acme","email":"alice@x.test","password":"wrong"}`, `{"tenant":"other","email":"alice@x.test","password":"correct horse battery"}`} {
		w, out := u.call("POST", "/api/v1/signin", body)
		if w.Code != 401 || out["reason"] != "invalid_credentials" || len(out) != 1 || sessionCookie(w) != nil {
			t.Fatalf("%s → %d %v", body, w.Code, out)
		}
	}
	w, out := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	if w.Code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	sc := sessionCookie(w)
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode || sc.MaxAge <= 0 {
		t.Fatalf("session cookie %+v", sc)
	}
	csrf := false
	for _, c := range w.Result().Cookies() {
		if c.Name == edge.CSRFCookie && !c.HttpOnly {
			csrf = true
		}
	}
	if !csrf {
		t.Fatal("csrf cookie must be issued with the session")
	}
	// Session info, token minting and offline verification.
	w, out = u.call("GET", "/api/v1/session", "", sc)
	if w.Code != 200 || out["operator"] != false || out["user"].(map[string]any)["email"] != "alice@x.test" || out["tenant"].(map[string]any)["slug"] != "acme" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/session", ""); w.Code != 401 {
		t.Fatal("no cookie")
	}
	w, out = u.call("POST", "/api/v1/session/token", "", sc)
	if w.Code != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("%d %v", w.Code, out)
	}
	keys, _ := authclient.ParseJWKS(u.ring.JWKSJSON())
	v := authclient.New(authclient.Config{Issuer: "https://auth.example.org"}, authclient.StaticKeys(keys), nil)
	_ = v.RefreshKeys(context.Background())
	id, err := v.Verify(context.Background(), out["access_token"].(string))
	if err != nil || id.UserID != "u1" || id.TenantID != tid || id.Roles[0] != "admin" || id.AMR[0] != "pwd" {
		t.Fatalf("%+v %v", id, err)
	}
	w, _ = u.call("GET", "/.well-known/jwks.json", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"kty":"OKP"`) || strings.Contains(w.Body.String(), `"d"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// A second session, list, revoke the other, sign out the current.
	w2, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	sc2 := sessionCookie(w2)
	w, _ = u.call("GET", "/api/v1/sessions", "", sc)
	var list []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != 200 || len(list) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var otherID string
	for _, s := range list {
		if s["current"] != true {
			otherID = s["id"].(string)
		}
	}
	if w, _ = u.call("POST", "/api/v1/sessions/"+otherID+"/revoke", "", sc); w.Code != 204 {
		t.Fatalf("revoke → %d", w.Code)
	}
	if w, _ = u.call("GET", "/api/v1/session", "", sc2); w.Code != 401 {
		t.Fatal("revoked session still valid")
	}
	if w, _ = u.call("POST", "/api/v1/sessions/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99/revoke", "", sc); w.Code != 404 {
		t.Fatalf("foreign session → %d", w.Code)
	}
	if w, _ = u.call("POST", "/api/v1/signout", "", sc); w.Code != 204 || sessionCookie(w).MaxAge != -1 {
		t.Fatalf("signout → %d", w.Code)
	}
	if w, _ = u.call("GET", "/api/v1/session", "", sc); w.Code != 401 {
		t.Fatal("signed-out session still valid")
	}
	if w, _ = u.call("POST", "/api/v1/signout", ""); w.Code != 204 {
		t.Fatal("signout without session is idempotent")
	}
}

func TestSigninLockoutStatus(t *testing.T) {
	u := newUS1(t)
	for i := 0; i < 3; i++ {
		u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"wrong"}`)
	}
	w, out := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	if w.Code != 423 || out["reason"] != "locked" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/signin/mfa", `{"challenge":"x","code":"000000"}`); w.Code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("%d %v", w.Code, out)
	}
}
