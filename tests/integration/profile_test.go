//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/go-freya/freya/transport/edge"
)

// upload sends raw bytes as the avatar.
func (e *Env) upload(path string, body []byte, contentType string) (int, http.Header, map[string]any) {
	e.T.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.Base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(edge.CSRFHeader, e.CSRF())
	req.Header.Set("Origin", e.Base)
	resp, err := e.Client.Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, resp.Header, out
}

func (e *Env) get(path string) (int, http.Header, []byte) {
	e.T.Helper()
	resp, err := e.Client.Get(e.Base + path)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// TestProfile: quickstart §3 — own profile and avatar end to end, platform
// surfaces carry the display name and avatar but never the phone, and
// cross-tenant access is answered as not found (SC-004, SC-005, SC-006, SC-007).
func TestProfile(t *testing.T) {
	e := Start(t)
	tid, dana := e.Seed("acme", "dana@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, dana, roles)
	if e.SignIn("acme", "dana@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	code, prof := e.JSON(http.MethodPut, "/api/v1/me/profile", map[string]string{"first_name": "Dana", "last_name": "Kovač", "phone": "+385 91 123 4567"})
	if code != 200 || prof["display_name"] != "Dana Kovač" || prof["phone"] != "+385911234567" {
		t.Fatalf("%d %v", code, prof)
	}
	// The session document and the exchanged identity carry the name, not the phone.
	_, sess := e.JSON(http.MethodGet, "/api/v1/session", nil)
	js, _ := json.Marshal(sess)
	if !strings.Contains(string(js), `"display_name":"Dana Kovač"`) || strings.Contains(string(js), "+385") {
		t.Fatalf("session document: %s", js)
	}
	a, err := e.App.Sessions.ByID(context.Background(), tid, sessionIDOf(t, e))
	if err != nil || a.DisplayName != "Dana Kovač" {
		t.Fatalf("identity %+v %v", a, err)
	}
	// Avatar corpus.
	png, _ := os.ReadFile("../fuzz/testdata/avatars/valid.png")
	code, hdr, up := e.upload("/api/v1/me/avatar", png, "image/png")
	if code != 200 || hdr.Get("X-Freya-Identity-Refresh") != "1" {
		t.Fatalf("upload %d %v", code, up)
	}
	url1 := up["avatar_url"].(string)
	code, hdr, body := e.get(url1)
	if code != 200 || hdr.Get("Content-Type") != "image/jpeg" || hdr.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(hdr.Get("Cache-Control"), "immutable") {
		t.Fatalf("avatar %d %v", code, hdr)
	}
	if bytes.Contains(body, []byte("Exif")) {
		t.Fatal("metadata survived")
	}
	for _, c := range []struct{ file, want string }{{"html-as.png", "unsupported_type"}, {"bomb-20000x20000.png", "too_large_dimensions"}, {"truncated.jpg", "decode_failed"}} {
		b, _ := os.ReadFile("../fuzz/testdata/avatars/" + c.file)
		if code, _, out := e.upload("/api/v1/me/avatar", b, "image/png"); code != 400 || out["reason"] != c.want {
			t.Fatalf("%s → %d %v", c.file, code, out)
		}
	}
	if code, _, _ := e.upload("/api/v1/me/avatar", make([]byte, 3<<20), "image/png"); code != 413 {
		t.Fatalf("oversized → %d", code)
	}
	exif, _ := os.ReadFile("../fuzz/testdata/avatars/exif-gps.jpg")
	code, _, up = e.upload("/api/v1/me/avatar", exif, "image/jpeg")
	if code != 200 || up["avatar_url"] == url1 {
		t.Fatalf("replace %d %v", code, up)
	}
	if code, _, _ := e.get(url1); code != 404 {
		t.Fatalf("old address must be gone: %d", code)
	}
	_, _, body = e.get(up["avatar_url"].(string))
	if bytes.Contains(body, []byte("Exif")) || bytes.Contains(body, []byte{0xff, 0xe1}) {
		t.Fatal("EXIF survived re-encoding")
	}
	a, _ = e.App.Sessions.ByID(context.Background(), tid, sessionIDOf(t, e))
	if a.AvatarURL != up["avatar_url"] {
		t.Fatalf("identity avatar %q vs %q", a.AvatarURL, up["avatar_url"])
	}
	// Another tenant: avatar and lookup are not found; a member of the same tenant sees name and avatar.
	tb, bobB := e.Seed("globex", "bob@globex.test", pw, "")
	rolesB := e.SeedRoles(tb)
	e.Bind(tb, bobB, rolesB)
	g := e.Browser()
	g.SignIn("globex", "bob@globex.test", pw)
	if code, _, _ := g.get(up["avatar_url"].(string)); code != 404 {
		t.Fatalf("cross-tenant avatar → %d", code)
	}
	if code, out := g.JSON(http.MethodGet, "/api/v1/users/"+dana, nil); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("cross-tenant lookup → %d %v", code, out)
	}
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	e.Bind(tid, carol, roles)
	c := e.Browser()
	c.SignIn("acme", "carol@acme.test", pw)
	code, pub := c.JSON(http.MethodGet, "/api/v1/users/"+dana, nil)
	if code != 200 || pub["display_name"] != "Dana Kovač" || pub["avatar_url"] != up["avatar_url"] || pub["phone"] != nil {
		t.Fatalf("lookup %d %v", code, pub)
	}
	if code, _, _ := c.get(up["avatar_url"].(string)); code != 200 {
		t.Fatalf("same-tenant avatar → %d", code)
	}
	// Anonymous fetch of the avatar is not found either.
	anon := e.Browser()
	if code, _, _ := anon.get(up["avatar_url"].(string)); code != 404 {
		t.Fatalf("anonymous avatar → %d", code)
	}
	// Audit: profile and avatar events, field names only.
	if n := e.AuditCount(tid, "profile_updated"); n < 1 {
		t.Fatalf("profile_updated events %d", n)
	}
	if n := e.AuditCount(tid, "avatar_updated"); n < 2 {
		t.Fatalf("avatar_updated events %d", n)
	}
}
