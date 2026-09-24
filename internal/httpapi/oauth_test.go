package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/oauth"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

func TestOAuthCodeFlowHandlers(t *testing.T) {
	u := newUS1(t)
	u.ms.AddClient(store.ClientApplication{ClientID: "spa", TenantID: tid, RedirectURIs: []string{"https://app.example.org/cb"}, Public: true})
	u.srv.RegisterOAuth(OAuthDeps{OAuth: oauth.New(u.ms, cache.New(cache.NewMemory()), token.NewIssuer(u.ring, "https://auth.example.org"), nil)})
	verifier := strings.Repeat("q", 50)
	q := url.Values{"response_type": {"code"}, "client_id": {"spa"}, "redirect_uri": {"https://app.example.org/cb"}, "state": {"s-1"}, "code_challenge": {oauth.Challenge(verifier)}, "code_challenge_method": {"S256"}}
	// Not signed in → bounced to the console with a same-origin return path.
	w, _ := u.call("GET", "/authorize?"+q.Encode(), "")
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/console/signin?next=%2Fauthorize") {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
	// Bad requests never redirect.
	bad := url.Values{}
	for k, v := range q {
		bad[k] = v
	}
	bad.Set("redirect_uri", "https://evil.example.org/cb")
	if w, out := u.call("GET", "/authorize?"+bad.Encode(), ""); w.Code != 400 || out["reason"] != "invalid_request" {
		t.Fatalf("%d %v", w.Code, out)
	}
	bad.Set("redirect_uri", "https://app.example.org/cb")
	bad.Del("state")
	if w, _ := u.call("GET", "/authorize?"+bad.Encode(), ""); w.Code != 400 {
		t.Fatalf("missing state → %d", w.Code)
	}
	// Sign in, then authorize → code on the registered redirect.
	sw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	sc := sessionCookie(sw)
	w, _ = u.call("GET", "/authorize?"+q.Encode(), "", sc)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Host != "app.example.org" || loc.Query().Get("state") != "s-1" || loc.Query().Get("code") == "" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
	code := loc.Query().Get("code")
	form := func(verifier, code string) (*httptest.ResponseRecorder, map[string]any) {
		body := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example.org/cb"}, "client_id": {"spa"}, "code_verifier": {verifier}}
		r := httptest.NewRequest("POST", "https://localhost/api/v1/oauth/token", strings.NewReader(body.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(edge.CSRFHeader, "n/a")
		rec := httptest.NewRecorder()
		u.srv.Handler().ServeHTTP(rec, r)
		return rec, decode(rec)
	}
	if w, out := form(strings.Repeat("z", 50), code); w.Code != 400 || out["reason"] != "invalid_grant" {
		t.Fatalf("wrong verifier → %d %v", w.Code, out)
	}
	if w, _ := form(verifier, code); w.Code != 400 {
		t.Fatal("burnt code must not be redeemable")
	}
	w, _ = u.call("GET", "/authorize?"+q.Encode(), "", sc)
	loc, _ = url.Parse(w.Header().Get("Location"))
	w, out := form(verifier, loc.Query().Get("code"))
	if w.Code != 200 || out["token_type"] != "Bearer" || out["access_token"] == "" {
		t.Fatalf("%d %v", w.Code, out)
	}
}

func decode(rec *httptest.ResponseRecorder) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}
