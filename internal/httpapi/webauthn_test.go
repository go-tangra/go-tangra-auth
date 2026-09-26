package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn/softkey"
)

const waOrigin = "https://auth.example.org"

type waEnv struct {
	*us1
	mfa  *mfa.Service
	keys *webauthn.Service
	aw   *audit.Writer
}

// withWebAuthn mounts the account (US4) and security-key routes on the US1
// harness; alice (admin) and bob (member) have passwords.
func withWebAuthn(t *testing.T, enabled bool) *waEnv {
	t.Helper()
	u := newUS1(t)
	h, _ := password.Hash("correct horse battery")
	u.ms.AddUser(store.User{ID: "u2", TenantID: tid, Email: "bob@x.test", DisplayName: "Bob", Status: "active", PasswordHash: &h})
	u.ms.SetRoles(tid, "u2", []string{"member"})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{5}, 32))
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(u.ms, nil)
	t.Cleanup(aw.Close)
	m := mfa.New(u.ms, c, env, aw, "Tangra")
	u.signin.SetMFA(m)
	u.signin.SetMethods(m)
	d := WebAuthnDeps{MFA: m, Signin: u.signin, Admin: user.NewAdmin(u.ms, u.sessions, aw), RPID: "auth.example.org"}
	var ks *webauthn.Service
	if enabled {
		var err error
		ks, err = webauthn.New(webauthn.Config{RPID: "auth.example.org", Origins: []string{waOrigin}, DisplayName: "Tangra", UserVerification: "preferred", Timeout: 5 * time.Minute}, u.ms, m, c, aw)
		if err != nil {
			t.Fatal(err)
		}
		u.signin.SetKeys(ks)
		d.Keys = ks
	}
	u.srv.RegisterUS4(US4Deps{MFA: m})
	u.srv.RegisterWebAuthn(d)
	return &waEnv{us1: u, mfa: m, keys: ks, aw: aw}
}

func (e *waEnv) signIn(t *testing.T, email string) *http.Cookie {
	t.Helper()
	w, out := e.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"`+email+`","password":"correct horse battery"}`)
	if w.Code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	return sessionCookie(w)
}

// register runs both registration calls with the soft key.
func (e *waEnv) register(t *testing.T, sc *http.Cookie, k *softkey.Key, name string) (int, map[string]any) {
	t.Helper()
	w, _ := e.call("POST", "/api/v1/me/mfa/webauthn/register/options", `{"name":"`+name+`"}`, sc)
	if w.Code != 200 {
		t.Fatalf("options %d %s", w.Code, w.Body)
	}
	resp, err := k.Create(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	w, out := e.call("POST", "/api/v1/me/mfa/webauthn/register", `{"credential":`+string(resp)+`}`, sc)
	return w.Code, out
}

func TestWebAuthnRegistrationRoutes(t *testing.T) {
	e := withWebAuthn(t, true)
	sc := e.signIn(t, "alice@x.test")
	w, out := e.call("GET", "/api/v1/me/mfa", "", sc)
	if w.Code != 200 || out["totp"] != false || len(out["keys"].([]any)) != 0 || out["required"] != false ||
		out["webauthn"].(map[string]any)["enabled"] != true || out["webauthn"].(map[string]any)["rp_id"] != "auth.example.org" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Name validation.
	for body, reason := range map[string]string{`{"name":"   "}`: "invalid_name", `{"name":"` + strings.Repeat("x", 65) + `"}`: "invalid_name", `{}`: "validation_failed"} {
		if w, out := e.call("POST", "/api/v1/me/mfa/webauthn/register/options", body, sc); w.Code != 400 || out["reason"] != reason {
			t.Errorf("%s → %d %v", body, w.Code, out)
		}
	}
	desk := softkey.New(waOrigin)
	code, out := e.register(t, sc, desk, "Desk")
	if code != 201 || out["key"].(map[string]any)["name"] != "Desk" || len(out["recovery_codes"].([]any)) != mfa.RecoveryCount {
		t.Fatalf("%d %v", code, out)
	}
	if strings.Contains(e.call2(t, "GET", "/api/v1/me/mfa", sc), base64url(desk.ID)) {
		t.Fatal("credential id exposed")
	}
	code, out = e.register(t, sc, softkey.New(waOrigin), "Travel")
	if code != 201 || out["recovery_codes"] != nil {
		t.Fatalf("second key: %d %v", code, out)
	}
	if w, out := e.call("POST", "/api/v1/me/mfa/webauthn/register/options", `{"name":"desk"}`, sc); w.Code != 409 || out["reason"] != "name_taken" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// The same credential again.
	if code, out := e.register(t, sc, desk, "Again"); code != 409 || out["reason"] != "already_registered" {
		t.Fatalf("%d %v", code, out)
	}
	// A failed ceremony is a 400, never a 401 (the console would sign out).
	evil := softkey.New("https://evil.example.org")
	if code, out := e.register(t, sc, evil, "Evil"); code != 400 || out["reason"] != "registration_failed" {
		t.Fatalf("%d %v", code, out)
	}
	if w, out := e.call("POST", "/api/v1/me/mfa/webauthn/register", `{"credential":{"id":"x","type":"public-key","response":{}}}`, sc); w.Code != 400 || out["reason"] != "registration_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Bounded bodies, closed objects.
	big := `{"credential":{"id":"x","type":"public-key","response":{"clientDataJSON":"` + strings.Repeat("A", MaxBodyBytes) + `"}}}`
	if w, _ := e.call("POST", "/api/v1/me/mfa/webauthn/register", big, sc); w.Code != 400 {
		t.Fatalf("oversized body → %d", w.Code)
	}
	if w, _ := e.call("POST", "/api/v1/me/mfa/webauthn/register", `{"credential":{"id":"x","type":"public-key","response":{}},"extra":1}`, sc); w.Code != 400 {
		t.Fatalf("unknown field → %d", w.Code)
	}
	// Signed-in only; the CSRF header is required on mutations.
	if w, out := e.call("GET", "/api/v1/me/mfa", ""); w.Code != 401 || out["reason"] != "unauthenticated" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := e.call("POST", "/api/v1/me/mfa/webauthn/register/options", `{"name":"x"}`); w.Code != 401 {
		t.Fatalf("anonymous options → %d", w.Code)
	}
	r := httptest.NewRequest("POST", "https://localhost/api/v1/me/mfa/webauthn/register/options", strings.NewReader(`{"name":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(sc)
	rw := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rw, r)
	if rw.Code != 400 {
		t.Fatalf("without CSRF header → %d", rw.Code)
	}
	// Key limit.
	for i := 0; i < webauthn.MaxKeys-2; i++ {
		if code, _ := e.register(t, sc, softkey.New(waOrigin), "K"+string(rune('a'+i))); code != 201 {
			t.Fatal(code)
		}
	}
	if w, out := e.call("POST", "/api/v1/me/mfa/webauthn/register/options", `{"name":"eleven"}`, sc); w.Code != 409 || out["reason"] != "key_limit" {
		t.Fatalf("%d %v", w.Code, out)
	}
}

func (e *waEnv) call2(t *testing.T, method, path string, c *http.Cookie) string {
	t.Helper()
	w, _ := e.call(method, path, "", c)
	return w.Body.String()
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestWebAuthnSigninRoutes(t *testing.T) {
	e := withWebAuthn(t, true)
	sc := e.signIn(t, "alice@x.test")
	desk := softkey.New(waOrigin)
	_, reg := e.register(t, sc, desk, "Desk")
	recovery := reg["recovery_codes"].([]any)[0].(string)
	start := func() string {
		w, out := e.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
		if w.Code != 200 || out["mfa_required"] != true {
			t.Fatalf("%d %v", w.Code, out)
		}
		m := out["mfa_methods"].([]any)
		if len(m) != 2 || m[0] != "webauthn" || m[1] != "recovery" {
			t.Fatalf("methods %v", m)
		}
		return out["challenge"].(string)
	}
	ch := start()
	if w, out := e.call("POST", "/api/v1/signin/mfa/webauthn/options", `{"challenge":"nope"}`); w.Code != 401 || out["reason"] != "invalid_challenge" {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, _ := e.call("POST", "/api/v1/signin/mfa/webauthn/options", `{"challenge":"`+ch+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"allowCredentials"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	resp, _ := desk.Get(w.Body.Bytes())
	w, out := e.call("POST", "/api/v1/signin/mfa/webauthn", `{"challenge":"`+ch+`","credential":`+string(resp)+`}`)
	if w.Code != 200 || out["signed_in"] != true || sessionCookie(w) == nil {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Token amr carries the hardware key.
	ks := sessionCookie(w)
	w, out = e.call("POST", "/api/v1/session/token", "", ks)
	if w.Code != 200 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if claims := decodeJWT(t, out["access_token"].(string)); !strings.Contains(claims, `"amr":["pwd","hwk"]`) {
		t.Fatalf("claims %s", claims)
	}
	// Failures: 401 mfa_failed, counted toward the lockout (threshold 3).
	ch = start()
	evil := *desk
	evil.Origin = "https://evil.example.org"
	for i := 0; i < 2; i++ {
		w, _ := e.call("POST", "/api/v1/signin/mfa/webauthn/options", `{"challenge":"`+ch+`"}`)
		resp, _ := evil.Get(w.Body.Bytes())
		if w, out := e.call("POST", "/api/v1/signin/mfa/webauthn", `{"challenge":"`+ch+`","credential":`+string(resp)+`}`); w.Code != 401 || out["reason"] != "mfa_failed" {
			t.Fatalf("%d %v", w.Code, out)
		}
	}
	// A recovery code still works for a key-only user.
	if w, out := e.call("POST", "/api/v1/signin/mfa", `{"challenge":"`+ch+`","code":"`+recovery+`"}`); w.Code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Clone signal: 401 key_flagged.
	ch = start()
	clone := *desk
	clone.FreezeCounter = true
	w, _ = e.call("POST", "/api/v1/signin/mfa/webauthn/options", `{"challenge":"`+ch+`"}`)
	resp, _ = clone.Get(w.Body.Bytes())
	if w, out := e.call("POST", "/api/v1/signin/mfa/webauthn", `{"challenge":"`+ch+`","credential":`+string(resp)+`}`); w.Code != 401 || out["reason"] != "key_flagged" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Lockout reached: 423 on both routes.
	for i := 0; i < 3; i++ {
		_, _ = e.call("POST", "/api/v1/signin/mfa", `{"challenge":"`+ch+`","code":"000000"}`)
	}
	w, out = e.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	if w.Code != 423 || out["reason"] != "locked" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := e.call("POST", "/api/v1/signin/mfa/webauthn", `{"challenge":"x"}`); w.Code != 400 {
		t.Fatalf("missing credential → %d", w.Code)
	}
}

func decodeJWT(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWebAuthnManagementRoutes(t *testing.T) {
	e := withWebAuthn(t, true)
	sc := e.signIn(t, "alice@x.test")
	desk := softkey.New(waOrigin)
	_, reg := e.register(t, sc, desk, "Desk")
	deskID := reg["key"].(map[string]any)["id"].(string)
	recovery := reg["recovery_codes"].([]any)
	travel := softkey.New(waOrigin)
	_, reg2 := e.register(t, sc, travel, "Travel")
	travelID := reg2["key"].(map[string]any)["id"].(string)
	// Rename.
	if w, out := e.call("PATCH", "/api/v1/me/mfa/webauthn/"+deskID, `{"name":"Office"}`, sc); w.Code != 200 || out["key"].(map[string]any)["name"] != "Office" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := e.call("PATCH", "/api/v1/me/mfa/webauthn/"+deskID, `{"name":"travel"}`, sc); w.Code != 409 || out["reason"] != "name_taken" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := e.call("PATCH", "/api/v1/me/mfa/webauthn/"+store.NewID(), `{"name":"x"}`, sc); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Bob cannot rename or remove alice's key.
	bob := e.signIn(t, "bob@x.test")
	if w, _ := e.call("PATCH", "/api/v1/me/mfa/webauthn/"+deskID, `{"name":"mine"}`, bob); w.Code != 404 {
		t.Fatalf("foreign rename → %d", w.Code)
	}
	if w, _ := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+deskID, `{"code":"`+recovery[0].(string)+`"}`, bob); w.Code != 404 {
		t.Fatalf("foreign delete → %d", w.Code)
	}
	// Removal needs a current factor; a wrong one is 403 and counts.
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+deskID, `{}`, sc); w.Code != 403 || out["reason"] != "confirmation_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+deskID, `{"code":"ZZZZZ-ZZZZZ"}`, sc); w.Code != 403 || out["reason"] != "confirmation_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Confirmed with the other key (step-up).
	w, _ := e.call("POST", "/api/v1/me/mfa/stepup/options", "", sc)
	if w.Code != 200 {
		t.Fatalf("stepup %d %s", w.Code, w.Body)
	}
	resp, _ := travel.Get(w.Body.Bytes())
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+deskID, `{"credential":`+string(resp)+`}`, sc); w.Code != 204 {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Adding TOTP next to the last key, then removing the key with a TOTP code.
	w, out := e.call("POST", "/api/v1/me/mfa/enroll", "", sc)
	secret := out["secret"].(string)
	c, _ := totp.GenerateCode(secret, time.Now())
	if w, out = e.call("POST", "/api/v1/me/mfa/confirm", `{"code":"`+c+`"}`, sc); w.Code != 200 || out["recovery_codes"] != nil {
		t.Fatalf("totp next to a key must keep the codes: %d %v", w.Code, out)
	}
	w, out = e.call("GET", "/api/v1/me/mfa", "", sc)
	if out["totp"] != true || len(out["keys"].([]any)) != 1 || out["recovery_codes_left"].(float64) != float64(mfa.RecoveryCount) {
		t.Fatalf("%v", out)
	}
	c, _ = totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+travelID, `{"code":"`+c+`"}`, sc); w.Code != 204 {
		t.Fatalf("%d %v", w.Code, out)
	}
	e.aw.Flush()
	removed := 0
	for _, r := range e.ms.AuditRows {
		if r.EventType == string(audit.MFARemoved) && r.Outcome == "ok" && strings.Contains(string(r.Details), "webauthn") {
			removed++
		}
	}
	if removed != 2 {
		t.Fatalf("mfa_removed audited %d times", removed)
	}
	// Required policy: the last factor stays (409), no key to step up with (409).
	tn, _ := e.ms.Tenant(t.Context(), tid)
	tn.Policy = []byte(`{"mfa_required":true,"lockout_threshold":3,"lockout_duration":"5m"}`)
	e.ms.AddTenant(tn)
	bobKey := softkey.New(waOrigin)
	_, regB := e.register(t, bob, bobKey, "Only")
	w, _ = e.call("POST", "/api/v1/me/mfa/stepup/options", "", bob)
	resp, _ = bobKey.Get(w.Body.Bytes())
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+regB["key"].(map[string]any)["id"].(string), `{"credential":`+string(resp)+`}`, bob); w.Code != 409 || out["reason"] != "last_factor_required" {
		t.Fatalf("%d %v", w.Code, out)
	}
	h, _ := password.Hash("correct horse battery")
	e.ms.AddUser(store.User{ID: "u3", TenantID: tid, Email: "dave@x.test", Status: "active", PasswordHash: &h})
	dave := e.signIn(t, "dave@x.test")
	if w, out := e.call("POST", "/api/v1/me/mfa/stepup/options", "", dave); w.Code != 409 || out["reason"] != "no_keys" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Lockout from wrong confirmations: 423.
	_, regB2 := e.register(t, bob, softkey.New(waOrigin), "Second")
	id2 := regB2["key"].(map[string]any)["id"].(string)
	for i := 0; i < 3; i++ {
		_, _ = e.call("DELETE", "/api/v1/me/mfa/webauthn/"+id2, `{"code":"ZZZZZ-ZZZZZ"}`, bob)
	}
	if w, out := e.call("DELETE", "/api/v1/me/mfa/webauthn/"+id2, `{"code":"ZZZZZ-ZZZZZ"}`, bob); w.Code != 423 || out["reason"] != "locked" {
		t.Fatalf("%d %v", w.Code, out)
	}
}

func TestWebAuthnAdminRoutes(t *testing.T) {
	e := withWebAuthn(t, true)
	bob := e.signIn(t, "bob@x.test")
	k := softkey.New(waOrigin)
	e.register(t, bob, k, "Bob desk")
	alice := e.signIn(t, "alice@x.test")
	w, out := e.call("GET", "/api/v1/admin/users/u2/mfa", "", alice)
	if w.Code != 200 || out["totp"] != false || out["recovery_codes_left"].(float64) != float64(mfa.RecoveryCount) {
		t.Fatalf("%d %v", w.Code, out)
	}
	keys := out["keys"].([]any)
	key := keys[0].(map[string]any)
	if len(keys) != 1 || key["name"] != "Bob desk" || key["flagged"] != false {
		t.Fatalf("%v", keys)
	}
	if _, ok := key["id"]; ok {
		t.Fatal("admin view exposes the key id")
	}
	if strings.Contains(w.Body.String(), base64url(k.ID)) {
		t.Fatal("credential id exposed")
	}
	// Members cannot view or reset; self and unknown are refused.
	if w, _ := e.call("GET", "/api/v1/admin/users/u1/mfa", "", bob); w.Code != 403 {
		t.Fatalf("member view → %d", w.Code)
	}
	if w, _ := e.call("POST", "/api/v1/admin/users/u1/mfa/reset", "", bob); w.Code != 403 {
		t.Fatalf("member reset → %d", w.Code)
	}
	if w, out := e.call("POST", "/api/v1/admin/users/u1/mfa/reset", "", alice); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("self reset → %d %v", w.Code, out)
	}
	if w, _ := e.call("GET", "/api/v1/admin/users/nobody/mfa", "", alice); w.Code != 404 {
		t.Fatalf("unknown → %d", w.Code)
	}
	if w, _ := e.call("POST", "/api/v1/admin/users/nobody/mfa/reset", "", alice); w.Code != 404 {
		t.Fatalf("unknown reset → %d", w.Code)
	}
	// Reset: factors gone, sessions ended, audited with the admin as actor.
	if w, out := e.call("POST", "/api/v1/admin/users/u2/mfa/reset", "", alice); w.Code != 204 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := e.call("GET", "/api/v1/session", "", bob); w.Code != 401 {
		t.Fatal("bob's session must end")
	}
	w, out = e.call("GET", "/api/v1/admin/users/u2/mfa", "", alice)
	if len(out["keys"].([]any)) != 0 || out["recovery_codes_left"].(float64) != 0 {
		t.Fatalf("%v", out)
	}
	e.aw.Flush()
	found := false
	for _, r := range e.ms.AuditRows {
		if r.EventType == string(audit.MFAReset) && r.Outcome == "ok" && r.ActorUserID != nil && *r.ActorUserID == "u1" && r.SubjectID != nil && *r.SubjectID == "u2" {
			found = true
		}
	}
	if !found {
		t.Fatal("mfa_reset not audited")
	}
	// Sign-in after the reset asks for no second step.
	if w, out := e.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`); w.Code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
}

// Keys disabled: the routes answer 404 webauthn_disabled; the account view
// says so; sign-in never offers keys.
func TestWebAuthnDisabled(t *testing.T) {
	e := withWebAuthn(t, false)
	sc := e.signIn(t, "alice@x.test")
	if w, out := e.call("GET", "/api/v1/me/mfa", "", sc); w.Code != 200 || out["webauthn"].(map[string]any)["enabled"] != false {
		t.Fatalf("%d %v", w.Code, out)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/v1/me/mfa/webauthn/register/options", `{"name":"x"}`},
		{"POST", "/api/v1/me/mfa/webauthn/register", `{"credential":{"id":"x","type":"public-key","response":{}}}`},
		{"PATCH", "/api/v1/me/mfa/webauthn/" + store.NewID(), `{"name":"x"}`},
		{"DELETE", "/api/v1/me/mfa/webauthn/" + store.NewID(), `{}`},
		{"POST", "/api/v1/me/mfa/stepup/options", ""},
	} {
		if w, out := e.call(c.method, c.path, c.body, sc); w.Code != 404 || out["reason"] != "webauthn_disabled" {
			t.Errorf("%s %s → %d %v", c.method, c.path, w.Code, out)
		}
	}
	if w, out := e.call("POST", "/api/v1/signin/mfa/webauthn/options", `{"challenge":"x"}`); w.Code != 401 || out["reason"] != "invalid_challenge" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := e.call("POST", "/api/v1/signin/mfa/webauthn", `{"challenge":"x","credential":{"id":"x","type":"public-key","response":{}}}`); w.Code != 401 || out["reason"] != "mfa_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
}
