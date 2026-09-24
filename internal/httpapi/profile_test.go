package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

func withProfiles(t *testing.T, u *us1) *audit.Writer {
	t.Helper()
	aw, _ := withUS2(t, u)
	u.ms.AddUser(store.User{ID: "u9", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", Email: "f@x.test", Status: "active"})
	c := cache.New(cache.NewMemory())
	limits := user.AvatarLimits{MaxBytes: 2 << 20, MaxPixels: 4096 * 4096, Size: 64, Concurrency: 2}
	u.srv.RegisterProfiles(ProfileDeps{Profiles: user.NewProfiles(u.ms, aw), Avatars: user.NewAvatars(u.ms, aw, limits), Sessions: u.sessions, Cache: c, LookupRatePerMinute: 3, MaxAvatarBytes: limits.MaxBytes})
	return aw
}

// raw performs a non-JSON request (avatar upload / download).
func (u *us1) raw(method, path string, body []byte, contentType string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, bytes.NewReader(body))
	r = r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.5"))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		r.Header.Set(edge.CSRFHeader, "double-submit-token")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	u.srv.Handler().ServeHTTP(w, r)
	return w
}

func png(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../tests/fuzz/testdata/avatars/valid.png")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProfileHandlers(t *testing.T) {
	u := newUS1(t)
	aw := withProfiles(t, u)
	defer aw.Close()
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)

	if w, _ := u.call("GET", "/api/v1/me/profile", ""); w.Code != 401 {
		t.Fatalf("anonymous -> %d", w.Code)
	}
	w, out := u.call("GET", "/api/v1/me/profile", "", bob)
	if w.Code != 200 || out["email"] != "bob@x.test" || out["phone"] != "" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Validation from the schema (length, unknown fields) and from the service (phone, control chars).
	for _, body := range []string{`{"first_name":"` + strings.Repeat("x", 101) + `"}`, `{"extra":1}`, `{"first_name":"a\tb"}`} {
		if w, out := u.call("PUT", "/api/v1/me/profile", body, bob); w.Code != 400 || out["reason"] != "validation_failed" {
			t.Fatalf("%s -> %d %v", body, w.Code, out)
		}
	}
	if w, out := u.call("PUT", "/api/v1/me/profile", `{"phone":"12345"}`, bob); w.Code != 400 || out["reason"] != "invalid_phone" {
		t.Fatalf("phone -> %d %v", w.Code, out)
	}
	// Update: explicit display name kept, normalised phone, refresh header, no phone in the session document.
	w, out = u.call("PUT", "/api/v1/me/profile", `{"first_name":" Bob ","last_name":"Kovac","phone":"+385 91 123 4567"}`, bob)
	if w.Code != 200 || out["display_name"] != "Bob" || out["phone"] != "+385911234567" || out["first_name"] != "Bob" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w.Header().Get(IdentityRefreshHeader) != "1" {
		t.Fatal("self mutation must ask the gateway to refresh the identity")
	}
	w, out = u.call("GET", "/api/v1/session", "", bob)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if js, _ := json.Marshal(out); strings.Contains(string(js), "+385") || strings.Contains(string(js), "phone") {
		t.Fatalf("phone leaked into the session document: %s", js)
	}
	if out["user"].(map[string]any)["first_name"] != "Bob" {
		t.Fatalf("session document must carry the names: %v", out)
	}
	// Explicit display name override, then clearing it returns to derivation.
	if w, out := u.call("PUT", "/api/v1/me/profile", `{"first_name":"Bob","last_name":"Kovac","display_name":"Robert"}`, bob); w.Code != 200 || out["display_name"] != "Robert" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/me/profile", `{"first_name":"Bob","last_name":"Kovac","display_name":""}`, bob); w.Code != 200 || out["display_name"] != "Bob Kovac" {
		t.Fatalf("%d %v", w.Code, out)
	}

	// Avatar: upload, fetch with cache headers, replace changes the URL, stale is 404, remove is idempotent.
	w = u.raw("PUT", "/api/v1/me/avatar", png(t), "image/png", bob)
	if w.Code != 200 || w.Header().Get(IdentityRefreshHeader) != "1" {
		t.Fatalf("upload -> %d %s", w.Code, w.Body.String())
	}
	var up map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &up)
	url1 := up["avatar_url"]
	if !strings.HasPrefix(url1, "/api/v1/users/u2/avatar/") {
		t.Fatal(url1)
	}
	w = u.raw("GET", url1, nil, "", bob)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), "inline") {
		t.Fatalf("avatar headers %d %v", w.Code, w.Header())
	}
	if w := u.raw("GET", url1, nil, ""); w.Code != 404 {
		t.Fatalf("anonymous avatar fetch -> %d (must be uniform not_found)", w.Code)
	}
	jpg, _ := os.ReadFile("../../tests/fuzz/testdata/avatars/valid.jpg")
	w = u.raw("PUT", "/api/v1/me/avatar", jpg, "image/jpeg", bob) // a different picture -> a different address
	_ = json.Unmarshal(w.Body.Bytes(), &up)
	if w.Code != 200 || up["avatar_url"] == url1 {
		t.Fatalf("replace must change the address: %d %s", w.Code, up["avatar_url"])
	}
	if w := u.raw("GET", url1, nil, "", bob); w.Code != 404 {
		t.Fatalf("stale address -> %d", w.Code)
	}
	for body, want := range map[string]string{"<html>": "unsupported_type", string(png(t)[:20]): "decode_failed"} {
		w := u.raw("PUT", "/api/v1/me/avatar", []byte(body), "image/png", bob)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != 400 || out["reason"] != want {
			t.Fatalf("%q -> %d %v", body[:5], w.Code, out)
		}
	}
	if w := u.raw("PUT", "/api/v1/me/avatar", make([]byte, 3<<20), "image/png", bob); w.Code != 413 {
		t.Fatalf("oversized -> %d %s", w.Code, w.Body.String())
	}
	if w := u.raw("DELETE", "/api/v1/me/avatar", nil, "", bob); w.Code != 204 {
		t.Fatalf("remove -> %d", w.Code)
	}
	if w := u.raw("DELETE", "/api/v1/me/avatar", nil, "", bob); w.Code != 204 {
		t.Fatalf("remove again -> %d", w.Code)
	}
	if w, out := u.call("GET", "/api/v1/me/profile", "", bob); out["avatar_url"] != "" {
		t.Fatalf("%d %v", w.Code, out)
	}

	// Lookup: same tenant only, uniform 404, batch omits foreign ids, rate limited.
	if w, out := u.call("GET", "/api/v1/users/u1", "", bob); w.Code != 200 || out["display_name"] != "Alice" || out["phone"] != nil {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/users/u9", "", bob); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("foreign -> %d %v", w.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/users/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00", "", bob); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("unknown -> %d %v", w.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/users/u1", "", bob); w.Code != 429 || out["reason"] != "rate_limited" {
		t.Fatalf("4th lookup in the window -> %d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/users/lookup", `{"ids":["u1","u9","u2"]}`, bob); w.Code != 429 {
		t.Fatalf("batch shares the limit -> %d", w.Code)
	}
}

func TestSearchUsers(t *testing.T) {
	u := newUS1(t)
	aw := withProfiles(t, u)
	defer aw.Close()
	u.ms.AddUser(store.User{ID: "u3", TenantID: tid, Email: "carol@x.test", DisplayName: "Carol", FirstName: "Carol", LastName: "Zed", Phone: "+15550001", Status: "active"})
	u.ms.AddUser(store.User{ID: "u4", TenantID: tid, Email: "dave@x.test", DisplayName: "Dave", Status: "deactivated"})
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)
	if w, out := u.call("GET", "/api/v1/users?q=x", "", bob); w.Code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("short q -> %d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/users", "", bob); w.Code != 400 {
		t.Fatalf("missing q -> %d", w.Code)
	}
	w := u.raw("GET", "/api/v1/users?q=zed", nil, "", bob)
	var page struct{ Items []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || len(page.Items) != 1 || page.Items[0]["id"] != "u3" || page.Items[0]["email"] != "carol@x.test" || page.Items[0]["phone"] != nil {
		t.Fatalf("by last name -> %d %s", w.Code, w.Body.String())
	}
	// Email match, deactivated and foreign users excluded, ordered by display name.
	w = u.raw("GET", "/api/v1/users?q=x.test", nil, "", bob)
	page.Items = nil
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || len(page.Items) != 3 || page.Items[0]["display_name"] != "Alice" || page.Items[2]["display_name"] != "Carol" {
		t.Fatalf("by email -> %d %s", w.Code, w.Body.String())
	}
	// Shares the lookup rate (3/min in this harness): the fourth counted call is refused.
	if w, _ := u.call("GET", "/api/v1/users/u1", "", bob); w.Code != 200 {
		t.Fatalf("lookup -> %d", w.Code)
	}
	if w, out := u.call("GET", "/api/v1/users?q=ali", "", bob); w.Code != 429 || out["reason"] != "rate_limited" {
		t.Fatalf("rate -> %d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/users?q=ali", ""); w.Code != 401 {
		t.Fatalf("anonymous -> %d", w.Code)
	}
}
