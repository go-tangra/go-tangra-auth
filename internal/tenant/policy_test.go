package tenant

import (
	"strings"
	"testing"
	"time"
)

func TestPolicyDefaultsAndValidation(t *testing.T) {
	p, err := ParsePolicy(nil, false)
	if err != nil || p != DefaultPolicy() {
		t.Fatal(p, err)
	}
	p, err = ParsePolicy([]byte(`{"session_lifetime":"2h","idle_timeout":"30m","password_min_length":16}`), true)
	if err != nil || p.SessionLifetime.D() != 2*time.Hour || p.IdleTimeout.D() != 30*time.Minute || p.PasswordMinLength != 16 || !p.MFARequired {
		t.Fatalf("%+v %v", p, err)
	}
	if !strings.Contains(string(p.JSON()), `"session_lifetime":"2h0m0s"`) {
		t.Fatalf("json %s", p.JSON())
	}
	for _, bad := range []string{`{"session_lifetime":"25h"}`, `{"idle_timeout":"9h"}`, `{"access_token_lifetime":"16m"}`, `{"password_min_length":7}`,
		`{"lockout_threshold":2}`, `{"lockout_threshold":21}`, `{"lockout_duration":"30s"}`, `{"lockout_duration":"2h"}`, `{"session_lifetime":"soon"}`, `not json`} {
		if _, err := ParsePolicy([]byte(bad), false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
