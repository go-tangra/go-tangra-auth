//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestMFA(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	if e.SignIn("acme", "alice@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, enr := e.JSON(http.MethodPost, "/api/v1/me/mfa/enroll", nil)
	secret := enr["secret"].(string)
	code, _ := totp.GenerateCode(secret, time.Now())
	st, out := e.JSON(http.MethodPost, "/api/v1/me/mfa/confirm", map[string]string{"code": code})
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	recovery := out["recovery_codes"].([]any)[0].(string)
	e.JSON(http.MethodPost, "/api/v1/signout", nil)
	st, out = e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": pw})
	if st != 200 || out["mfa_required"] != true {
		t.Fatalf("%d %v", st, out)
	}
	ch := out["challenge"].(string)
	if st, _ := e.JSON(http.MethodPost, "/api/v1/signin/mfa", map[string]string{"challenge": ch, "code": recovery}); st != 200 {
		t.Fatal("recovery code")
	}
	e.JSON(http.MethodPost, "/api/v1/signout", nil)
	_, out = e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": pw})
	if st, _ := e.JSON(http.MethodPost, "/api/v1/signin/mfa", map[string]string{"challenge": out["challenge"].(string), "code": recovery}); st != 401 {
		t.Fatal("recovery code reused")
	}
}

func TestPasswordChange(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	if e.SignIn("acme", "alice@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	b := e.Browser()
	if b.SignIn("acme", "alice@acme.test", pw) != 200 {
		t.Fatal("second sign-in")
	}
	if st, _ := e.JSON(http.MethodPost, "/api/v1/me/password", map[string]string{"current_password": pw, "new_password": "a-brand-new-password"}); st != 204 {
		t.Fatal(st)
	}
	if st, _ := b.JSON(http.MethodGet, "/api/v1/session", nil); st != 401 {
		t.Fatal("other session survived")
	}
	if st, _ := e.JSON(http.MethodGet, "/api/v1/session", nil); st != 200 {
		t.Fatal("current session ended")
	}
}

func TestRecovery(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	if st, _ := e.JSON(http.MethodPost, "/api/v1/recovery", map[string]string{"tenant": "acme", "email": "alice@acme.test"}); st != 202 {
		t.Fatal(st)
	}
	mail := e.LastMail("alice@acme.test")
	tok := strings.TrimSpace(strings.Split(mail[strings.Index(mail, "token=")+6:], "\n")[0])
	if st, _ := e.JSON(http.MethodPost, "/api/v1/recovery/complete", map[string]string{"token": tok, "new_password": "yet-another-long-password"}); st != 204 {
		t.Fatal(st)
	}
	if st, _ := e.JSON(http.MethodPost, "/api/v1/recovery/complete", map[string]string{"token": tok, "new_password": "yet-another-long-password"}); st != 400 {
		t.Fatal("token reused")
	}
	if e.SignIn("acme", "alice@acme.test", "yet-another-long-password") != 200 {
		t.Fatal("new password")
	}
}

func TestSessionsSelf(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	a, b := e.Browser(), e.Browser()
	if a.SignIn("acme", "alice@acme.test", pw) != 200 || b.SignIn("acme", "alice@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	req, _ := http.NewRequest(http.MethodGet, a.Base+"/api/v1/sessions", nil)
	resp, err := a.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sessions []map[string]any
	_ = jsonDecode(resp, &sessions)
	_ = resp.Body.Close()
	var other string
	for _, s := range sessions {
		if s["current"] != true {
			other = s["id"].(string)
		}
	}
	if st, _ := a.JSON(http.MethodPost, "/api/v1/sessions/"+other+"/revoke", nil); st != 204 {
		t.Fatal(st)
	}
	if st, _ := b.JSON(http.MethodGet, "/api/v1/session", nil); st != 401 {
		t.Fatal("revoked session alive")
	}
	if st, _ := a.JSON(http.MethodGet, "/api/v1/session", nil); st != 200 {
		t.Fatal("own session affected")
	}
}
