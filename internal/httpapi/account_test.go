package httpapi

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/mfa"
	"github.com/go-freya/freya/services/auth/internal/password"
)

func TestAccountAndRecoveryHandlers(t *testing.T) {
	u := newUS1(t)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{5}, 32))
	ob := email.NewOutbox(env, nullSender{}, nil, 3, nil)
	m := mfa.New(u.ms, cache.New(cache.NewMemory()), env, nil, "Freya")
	u.signin.SetMFA(m)
	ch := password.NewChanger(u.ms, u.sessions, nil)
	ch.SetPad(func(time.Time) {})
	rec := password.NewRecovery(u.ms, ob, u.sessions, nil, "https://auth.example.org")
	rec.SetPad(func(time.Time) {})
	u.srv.RegisterUS4(US4Deps{MFA: m, Changer: ch, Recovery: rec})

	sw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	sc := sessionCookie(sw)
	other, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	oc := sessionCookie(other)
	// Password change: wrong current, policy, success (other session ends, current survives).
	if w, out := u.call("POST", "/api/v1/me/password", `{"current_password":"nope","new_password":"a-brand-new-password"}`, sc); w.Code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/me/password", `{"current_password":"correct horse battery","new_password":"short"}`, sc); w.Code != 400 || out["reason"] != "password_policy" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/me/password", `{"current_password":"correct horse battery","new_password":"a-brand-new-password"}`, sc); w.Code != 204 {
		t.Fatalf("change → %d", w.Code)
	}
	if w, _ := u.call("GET", "/api/v1/session", "", oc); w.Code != 401 {
		t.Fatal("other session must end")
	}
	if w, _ := u.call("GET", "/api/v1/session", "", sc); w.Code != 200 {
		t.Fatal("current session must survive")
	}
	// MFA enrolment: enrol → confirm with a real code → recovery codes once → session shows mfa_enabled.
	w, out := u.call("POST", "/api/v1/me/mfa/enroll", "", sc)
	if w.Code != 200 || !strings.HasPrefix(out["otpauth_uri"].(string), "otpauth://totp/") {
		t.Fatalf("%d %v", w.Code, out)
	}
	secret := out["secret"].(string)
	if w, out := u.call("POST", "/api/v1/me/mfa/confirm", `{"code":"000000"}`, sc); w.Code != 401 || out["reason"] != "invalid_code" {
		t.Fatalf("%d %v", w.Code, out)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	w, out = u.call("POST", "/api/v1/me/mfa/confirm", `{"code":"`+code+`"}`, sc)
	if w.Code != 200 || len(out["recovery_codes"].([]any)) != mfa.RecoveryCount {
		t.Fatalf("%d %v", w.Code, out)
	}
	recovery := out["recovery_codes"].([]any)[0].(string)
	if w, out := u.call("GET", "/api/v1/session", "", sc); w.Code != 200 || out["user"].(map[string]any)["mfa_enabled"] != true || out["mfa_setup_required"] != false {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Next sign-in requires the second factor; a recovery code completes it once.
	w, out = u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"a-brand-new-password"}`)
	if w.Code != 200 || out["mfa_required"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	ch1 := out["challenge"].(string)
	w, out = u.call("POST", "/api/v1/signin/mfa", `{"challenge":"`+ch1+`","code":"`+recovery+`"}`)
	if w.Code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	_, out = u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"a-brand-new-password"}`)
	ch2 := out["challenge"].(string)
	if w, out := u.call("POST", "/api/v1/signin/mfa", `{"challenge":"`+ch2+`","code":"`+recovery+`"}`); w.Code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("reused recovery code → %d %v", w.Code, out)
	}
	// Regenerate and disable need a valid code.
	code, _ = totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if w, out := u.call("POST", "/api/v1/me/mfa/recovery-codes", `{"code":"`+code+`"}`, sc); w.Code != 200 || len(out["recovery_codes"].([]any)) != mfa.RecoveryCount {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/me/mfa/disable", `{"code":"123"}`, sc); w.Code != 401 || out["reason"] != "invalid_code" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Recovery: always 202; token from the queued mail resets the password once.
	if w, out := u.call("POST", "/api/v1/recovery", `{"tenant":"acme","email":"ghost@x.test"}`); w.Code != 202 || out["queued"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/recovery", `{"tenant":"acme","email":"alice@x.test"}`); w.Code != 202 {
		t.Fatal("recovery request")
	}
	var last []byte
	for _, it := range u.ms.Outbox {
		if it.Kind == "recovery" {
			last = it.PayloadEnc
		}
	}
	p, _ := ob.Decode("alice@x.test", last)
	tok := strings.TrimSpace(strings.Split(p.Text[strings.Index(p.Text, "token=")+6:], "\n")[0])
	if w, out := u.call("POST", "/api/v1/recovery/complete", `{"token":"`+tok+`","new_password":"short"}`); w.Code != 400 || out["reason"] != "password_policy" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/recovery/complete", `{"token":"`+tok+`","new_password":"yet-another-long-password"}`); w.Code != 204 {
		t.Fatalf("complete → %d", w.Code)
	}
	if w, out := u.call("POST", "/api/v1/recovery/complete", `{"token":"`+tok+`","new_password":"yet-another-long-password"}`); w.Code != 400 || out["reason"] != "invalid_token" {
		t.Fatalf("reuse → %d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/session", "", sc); w.Code != 401 {
		t.Fatal("recovery must end every session")
	}
}
