package httpapi

import (
	"net/http"
	"testing"
	"time"
)

// POST /api/v1/session/refresh renews the session: a new cookie (the old one
// keeps working through the grace), a later absolute expiry and the idle
// timeout; a second refresh moments later only touches; without a session it
// answers 401 and clears the cookie.
func TestRefreshSession(t *testing.T) {
	u := newUS1(t)
	w, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	old := sessionCookie(w)
	if old == nil {
		t.Fatal("signed in without a session cookie")
	}
	w, out := u.call("POST", "/api/v1/session/refresh", "", old)
	if w.Code != 200 || out["renewed"] != true || out["session_id"] == "" || out["idle_timeout_seconds"] != float64(3600) {
		t.Fatalf("%d %v", w.Code, out)
	}
	exp, err := time.Parse(time.RFC3339, out["expires_at"].(string))
	if err != nil || time.Until(exp) < 7*time.Hour {
		t.Fatalf("expires_at %v (%v): the default 8 h lifetime starts again", out["expires_at"], err)
	}
	next := sessionCookie(w)
	if next == nil || next.Value == old.Value || !next.HttpOnly || !next.Secure || next.SameSite != http.SameSiteStrictMode || next.MaxAge <= 7*3600 {
		t.Fatalf("new session cookie %+v", next)
	}
	// Both cookies work during the grace; the new one is the session.
	for _, c := range []*http.Cookie{old, next} {
		if w, out := u.call("GET", "/api/v1/session", "", c); w.Code != 200 || out["session_id"] == "" {
			t.Fatalf("%d %v", w.Code, out)
		}
	}
	// Moments later (another tab): touched, not rotated; the cookie is left alone.
	w, out = u.call("POST", "/api/v1/session/refresh", "", next)
	if w.Code != 200 || out["renewed"] != false || sessionCookie(w) != nil {
		t.Fatalf("%d %v %+v", w.Code, out, sessionCookie(w))
	}
	// No session: 401, and the stale cookie is cleared.
	if w, out := u.call("POST", "/api/v1/session/refresh", ""); w.Code != 401 || out["reason"] != "unauthenticated" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/signout", "", next); w.Code != 204 {
		t.Fatal("sign-out")
	}
	w, _ = u.call("POST", "/api/v1/session/refresh", "", next)
	if c := sessionCookie(w); w.Code != 401 || (c != nil && c.MaxAge >= 0) {
		t.Fatalf("after sign-out: %d %+v", w.Code, c)
	}
}
