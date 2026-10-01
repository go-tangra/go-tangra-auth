package httpapi

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// The rules served to the invitation, reset and change-password pages come
// from the tenant's stored policy, carry policy parameters only, and a
// refusal names the violated rule without echoing the password.
func TestPasswordPolicyEndpoints(t *testing.T) {
	u := newUS1(t)
	// The tenant raised its minimum to 16.
	u.ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", DisplayName: "Acme", Status: "active", Kind: "customer",
		Policy: []byte(`{"lockout_threshold":3,"lockout_duration":"5m","password_min_length":16}`)})
	aw, ob := withUS2(t, u)
	defer aw.Close()
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{5}, 32))
	rob := email.NewOutbox(env, nullSender{}, nil, 3, nil)
	ch := password.NewChanger(u.ms, u.sessions, nil)
	ch.SetPad(func(time.Time) {})
	rec := password.NewRecovery(u.ms, rob, u.sessions, nil, "https://auth.example.org")
	rec.SetPad(func(time.Time) {})
	u.srv.RegisterUS4(US4Deps{MFA: mfa.New(u.ms, cache.New(cache.NewMemory()), env, nil, "Tangra"), Changer: ch, Recovery: rec})

	wantRules := func(t *testing.T, code int, out map[string]any) {
		t.Helper()
		if code != 200 || len(out) != 3 || out["min_length"] != float64(16) || out["max_length"] != float64(password.MaxLength) || out["reject_trivial"] != true {
			t.Fatalf("%d %v", code, out)
		}
	}
	wantRule := func(t *testing.T, code int, out map[string]any, rule string) {
		t.Helper()
		d, _ := out["detail"].(map[string]any)
		if code != 400 || out["reason"] != "password_policy" || d["rule"] != rule || len(d) != 1 {
			t.Fatalf("%d %v (want rule %s)", code, out, rule)
		}
	}

	// Invitation.
	sw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(sw)
	if w, _ := u.call("POST", "/api/v1/admin/invitations", `{"email":"new@x.test"}`, owner); w.Code != 202 {
		t.Fatalf("invite → %d", w.Code)
	}
	p, _ := ob.Decode("new@x.test", u.ms.Outbox[len(u.ms.Outbox)-1].PayloadEnc)
	tok := p.Link()[strings.Index(p.Link(), "token=")+6:]
	w, out := u.call("POST", "/api/v1/invitations/password-policy", `{"token":"`+tok+`"}`)
	wantRules(t, w.Code, out)
	for _, bad := range []string{`{"token":"nope"}`, `{"token":""}`} {
		if w, out := u.call("POST", "/api/v1/invitations/password-policy", bad); w.Code != 400 || out["reason"] != "invalid_token" {
			t.Fatalf("%s → %d %v", bad, w.Code, out)
		}
	}
	if w, _ := u.call("POST", "/api/v1/invitations/password-policy", `{"token":"`+tok+`","email":"x"}`); w.Code != 400 {
		t.Fatal("unknown fields must be refused")
	}
	for pw, rule := range map[string]string{"fifteen-chars-x": "min_length", strings.Repeat("z", 16): "reject_trivial", strings.Repeat("y", 1025): "max_length"} {
		w, out := u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"New","password":"`+pw+`"}`)
		wantRule(t, w.Code, out, rule)
		if strings.Contains(w.Body.String(), pw) {
			t.Fatal("the password must never be echoed")
		}
	}
	// Looking up the rules did not consume the token; acceptance does.
	if w, out := u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"New","password":"sixteen-chars-ok"}`); w.Code != 200 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/invitations/password-policy", `{"token":"`+tok+`"}`); w.Code != 400 || out["reason"] != "invalid_token" {
		t.Fatalf("redeemed token → %d %v", w.Code, out)
	}

	// Signed-in change.
	w, out = u.call("GET", "/api/v1/me/password-policy", "", owner)
	wantRules(t, w.Code, out)
	if w, _ := u.call("GET", "/api/v1/me/password-policy", ""); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	w, out = u.call("POST", "/api/v1/me/password", `{"current_password":"correct horse battery","new_password":"too-short"}`, owner)
	wantRule(t, w.Code, out, "min_length")

	// Reset link.
	if w, _ := u.call("POST", "/api/v1/recovery", `{"tenant":"acme","email":"bob@x.test"}`); w.Code != 202 {
		t.Fatalf("recovery → %d", w.Code)
	}
	rp, _ := rob.Decode("bob@x.test", u.ms.Outbox[len(u.ms.Outbox)-1].PayloadEnc)
	rtok := rp.Link()[strings.Index(rp.Link(), "token=")+6:]
	w, out = u.call("POST", "/api/v1/recovery/password-policy", `{"token":"`+rtok+`"}`)
	wantRules(t, w.Code, out)
	if w, out := u.call("POST", "/api/v1/recovery/password-policy", `{"token":"nope"}`); w.Code != 400 || out["reason"] != "invalid_token" {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, out = u.call("POST", "/api/v1/recovery/complete", `{"token":"`+rtok+`","new_password":"`+strings.Repeat(" ", 20)+`"}`)
	wantRule(t, w.Code, out, "reject_trivial")
	if w, _ := u.call("POST", "/api/v1/recovery/complete", `{"token":"`+rtok+`","new_password":"a-new-long-password"}`); w.Code != 204 {
		t.Fatalf("complete → %d", w.Code)
	}
}
