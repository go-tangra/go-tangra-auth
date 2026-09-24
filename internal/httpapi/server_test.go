package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/transport/edge"
)

type fakeSessions struct{ actor tenantctx.Actor }

func (f fakeSessions) Resolve(_ context.Context, secret string) (tenantctx.Actor, error) {
	if secret == "good" {
		return f.actor, nil
	}
	return tenantctx.Actor{}, errors.New("no session")
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	s, err := NewHandler(rt,
		WithSessions(fakeSessions{actor: tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: "t1"}}),
		WithConsole(fstest.MapFS{
			"index.html":    {Data: []byte(`<html><head><meta property="csp-nonce" nonce="__CSP_NONCE__"></head></html>`)},
			"assets/app.js": {Data: []byte("console.log(1)")},
			"favicon.ico":   {Data: []byte("ico")},
		}))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestDeclaredRoutesMountedAndValidated(t *testing.T) {
	s := newTestServer(t)
	if len(s.Declared()) < 30 {
		t.Fatalf("declared %d", len(s.Declared()))
	}
	// Unimplemented declared route → 501 with reason only.
	w := do(s, "POST", "/api/v1/signin", `{"tenant":"acme","email":"a@x.test","password":"pw"}`, nil)
	if w.Code != 501 || strings.TrimSpace(w.Body.String()) != `{"reason":"not_implemented"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Malformed / unknown-field / missing-field bodies are refused before any handler.
	called := false
	s.MustHandle("POST", "/api/v1/signin", func(w http.ResponseWriter, r *http.Request) {
		called = true
		var in struct {
			Tenant, Email, Password string
		}
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, 200, map[string]string{"ok": in.Tenant})
	})
	for _, body := range []string{`{`, `{"tenant":"acme","email":"a@x.test","password":"pw","extra":1}`, `{"tenant":"acme"}`, `[]`, strings.Repeat("a", MaxBodyBytes+10)} {
		called = false
		w = do(s, "POST", "/api/v1/signin", body, nil)
		if w.Code != 400 || !strings.HasPrefix(w.Body.String(), `{"reason":"`) || called {
			t.Fatalf("body %.20q → %d %s called=%v", body, w.Code, w.Body.String(), called)
		}
	}
	w = do(s, "POST", "/api/v1/signin", `{"tenant":"acme","email":"a@x.test","password":"pw"}`, nil)
	if w.Code != 200 || !called {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Wrong method on a declared path, unknown API path.
	if w = do(s, "PUT", "/api/v1/signin", "", nil); w.Code != 405 {
		t.Fatalf("405 expected, got %d", w.Code)
	}
	if w = do(s, "GET", "/api/v1/nope", "", nil); w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Undeclared routes cannot be mounted.
	if err := s.HandleFunc("GET", "/api/v1/secret", nil); err == nil {
		t.Fatal("undeclared route accepted")
	}
	if got := s.Implemented(); len(got) != 1 || got[0].Path != "/api/v1/signin" {
		t.Fatalf("implemented %v", got)
	}
}

func TestErrorEncoderNeverLeaks(t *testing.T) {
	s := newTestServer(t)
	s.MustHandle("GET", "/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		Fail(w, r, s.rt.Logger(), errors.New("pq: password authentication failed for user auth_app"))
	})
	w := do(s, "GET", "/api/v1/session", "", nil)
	if w.Code != 500 || strings.TrimSpace(w.Body.String()) != `{"reason":"internal"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	s.MustHandle("GET", "/api/v1/session", func(w http.ResponseWriter, r *http.Request) { Fail(w, r, nil, ErrForbidden) })
	if w = do(s, "GET", "/api/v1/session", "", nil); w.Code != 403 || !strings.Contains(w.Body.String(), "forbidden") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestSessionMiddlewareAndCookies(t *testing.T) {
	s := newTestServer(t)
	s.MustHandle("GET", "/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, 200, map[string]string{"user": a.UserID, "tenant": a.TenantID})
	})
	if w := do(s, "GET", "/api/v1/session", "", nil); w.Code != 401 {
		t.Fatalf("no cookie → %d", w.Code)
	}
	if w := do(s, "GET", "/api/v1/session", "", map[string]string{"Cookie": SessionCookie + "=bad"}); w.Code != 401 {
		t.Fatalf("bad cookie → %d", w.Code)
	}
	w := do(s, "GET", "/api/v1/session", "", map[string]string{"Cookie": SessionCookie + "=good"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"tenant":"t1"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "s", 3600)
	c := rec.Result().Cookies()[0]
	if c.Name != SessionCookie || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie attributes: %+v", c)
	}
	rec = httptest.NewRecorder()
	ClearSessionCookie(rec)
	if rec.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("clear")
	}
}

func TestConsoleServing(t *testing.T) {
	s := newTestServer(t)
	if w := do(s, "GET", "/", "", nil); w.Code != 302 || w.Header().Get("Location") != "/console/" {
		t.Fatalf("root → %d %q", w.Code, w.Header().Get("Location"))
	}
	w := do(s, "GET", "/console/signin?tenant=acme", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "csp-nonce") || strings.Contains(w.Body.String(), "__CSP_NONCE__") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %q %v", w.Code, w.Body.String(), w.Header())
	}
	issued := false
	for _, c := range w.Result().Cookies() {
		if c.Name == edge.CSRFCookie && c.Value != "" && !c.HttpOnly {
			issued = true
		}
	}
	if !issued {
		t.Fatal("a fresh browser must receive the CSRF cookie with the console page")
	}
	w = do(s, "GET", "/console/assets/app.js", "", nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w = do(s, "POST", "/console/signin", "", nil); w.Code != 405 {
		t.Fatalf("console POST → %d", w.Code)
	}
	// Non-canonical paths are redirected to their cleaned form, never resolved on disk.
	if w = do(s, "GET", "/console/../etc/passwd", "", nil); w.Code != 307 || w.Header().Get("Location") != "/etc/passwd" {
		t.Fatalf("traversal → %d %q", w.Code, w.Header().Get("Location"))
	}
	if w = do(s, "GET", "/console/etc/passwd", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "<html>") {
		t.Fatalf("unknown console path must fall back to the SPA: %d", w.Code)
	}
	if w = do(s, "GET", "/etc/passwd", "", nil); w.Code != 404 {
		t.Fatalf("outside the console prefix → %d", w.Code)
	}
	// Without a console, non-API paths are 404.
	bare, _ := NewHandler(testrt.New(t, testutil.MustCA("example.org"), "auth"))
	if w = do(bare, "GET", "/console/signin", "", nil); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

func TestRemoteServing(t *testing.T) {
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	s, err := NewHandler(rt, WithRemote(fstest.MapFS{
		"mf-manifest.json":     {Data: []byte(`{"id":"auth"}`)},
		"remoteEntry.js":       {Data: []byte("export {}")},
		"assets/x-ABCDEFGH.js": {Data: []byte("1")},
		"index.html":           {Data: []byte("<html>")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if w := do(s, "GET", "/ui/mf-manifest.json", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w := do(s, "GET", "/ui/assets/x-ABCDEFGH.js", "", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w := do(s, "GET", "/ui/remoteEntry.js", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	for _, p := range []string{"/ui/", "/ui/index.html", "/ui/missing.js", "/ui/assets/"} {
		if w := do(s, "GET", p, "", nil); w.Code != 404 {
			t.Fatalf("%s → %d", p, w.Code)
		}
	}
	if w := do(s, "POST", "/ui/mf-manifest.json", "", nil); w.Code == 200 {
		t.Fatal("POST served")
	}
}

// TestConsoleNonceBehindGateway: in gateway mode the page carries the nonce the
// gateway relays (its CSP names it); standalone, a relayed header is ignored
// and the edge nonce wins.
func TestConsoleNonceBehindGateway(t *testing.T) {
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	fs := fstest.MapFS{"index.html": {Data: []byte(`<meta property="csp-nonce" nonce="__CSP_NONCE__">`)}}
	gw, err := NewHandler(rt, WithConsole(fs), WithGatewayMode())
	if err != nil {
		t.Fatal(err)
	}
	w := do(gw, "GET", "/console/signin", "", map[string]string{"X-CSP-Nonce": "gw-nonce"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `nonce="gw-nonce"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, bad := range []string{`x"><script>alert(1)</script>`, strings.Repeat("a", 129)} {
		w = do(gw, "GET", "/console/signin", "", map[string]string{"X-CSP-Nonce": bad})
		if w.Code != 200 || !strings.Contains(w.Body.String(), `nonce=""`) {
			t.Fatalf("unsafe relayed nonce must be dropped: %s", w.Body.String())
		}
	}
	standalone, _ := NewHandler(rt, WithConsole(fs))
	r := httptest.NewRequest("GET", "https://localhost/console/signin", nil)
	r.Header.Set("X-CSP-Nonce", "spoof")
	r = r.WithContext(edge.WithNonce(r.Context(), "edge-nonce"))
	rec := httptest.NewRecorder()
	standalone.Handler().ServeHTTP(rec, r)
	if !strings.Contains(rec.Body.String(), `nonce="edge-nonce"`) || strings.Contains(rec.Body.String(), "spoof") {
		t.Fatalf("standalone must use its own edge nonce: %s", rec.Body.String())
	}
}
