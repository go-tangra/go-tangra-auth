//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/oauth"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

func TestOAuthCodeFlow(t *testing.T) {
	e := Start(t)
	tid, _ := e.Seed("acme", "alice@acme.test", pw, "")
	if err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.InsertClient(context.Background(), tx, store.ClientApplication{ClientID: "spa", TenantID: tid, DisplayName: "SPA", RedirectURIs: []string{"https://app.example.org/cb"}, Public: true})
	}); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 64)
	q := url.Values{"response_type": {"code"}, "client_id": {"spa"}, "redirect_uri": {"https://app.example.org/cb"}, "state": {"st"}, "code_challenge": {oauth.Challenge(verifier)}, "code_challenge_method": {"S256"}}
	noRedirect := *e.Client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// get returns the status and redirect target; the body is always closed.
	get := func(query url.Values) (int, string) {
		resp, err := noRedirect.Get(e.Base + "/authorize?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location")
	}
	if st, where := get(q); st != 302 || !strings.HasPrefix(where, "/console/signin?next=") {
		t.Fatalf("%d %q", st, where)
	}
	if code := e.SignIn("acme", "alice@acme.test", pw); code != 200 {
		t.Fatal(code)
	}
	st, where := get(q)
	loc, _ := url.Parse(where)
	if st != 302 || loc.Host != "app.example.org" || loc.Query().Get("state") != "st" {
		t.Fatalf("%d %q", st, where)
	}
	exchange := func(code, ver string) (int, map[string]any) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example.org/cb"}, "client_id": {"spa"}, "code_verifier": {ver}}
		req, _ := http.NewRequest(http.MethodPost, e.Base+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", e.Base)
		req.Header.Set("X-CSRF-Token", e.CSRF())
		r, err := e.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		out := map[string]any{}
		_ = jsonDecode(r, &out)
		return r.StatusCode, out
	}
	code := loc.Query().Get("code")
	if st, out := exchange(code, strings.Repeat("w", 64)); st != 400 || out["reason"] != "invalid_grant" {
		t.Fatalf("wrong verifier → %d %v", st, out)
	}
	if st, _ := exchange(code, verifier); st != 400 {
		t.Fatal("reused code accepted")
	}
	_, where = get(q)
	loc, _ = url.Parse(where)
	if st, out := exchange(loc.Query().Get("code"), verifier); st != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("%d %v", st, out)
	}
	bad := url.Values{}
	for k, v := range q {
		bad[k] = v
	}
	bad.Set("redirect_uri", "https://evil.example.org/cb")
	if st, _ := get(bad); st != 400 {
		t.Fatalf("unregistered redirect → %d", st)
	}
	bad.Set("redirect_uri", "https://app.example.org/cb")
	bad.Del("state")
	if st, _ := get(bad); st != 400 {
		t.Fatalf("missing state → %d", st)
	}
}
