package tenant

import "testing"

func TestParseSlug(t *testing.T) {
	for _, ok := range []string{"acme", "acme-corp", "a1", "9"} {
		if _, err := ParseSlug(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Acme", "-a", "a-", "a_b", "api", "admin", string(make([]byte, 64))} {
		if _, err := ParseSlug(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSlugFromEmail(t *testing.T) {
	for in, want := range map[string]string{
		"jane@acme.com":        "acme",
		"Jane@ACME.com":        "acme",
		"jane@mail.acme.co.uk": "acme",
		"jane@acme-corp.io":    "acme-corp",
		"  jane@sub.x.test ":   "x",
		"ops@platform.example": "platform",
		"jane@acme.com.":       "acme",
	} {
		if got, err := SlugFromEmail(in); err != nil || got != want {
			t.Errorf("%q → %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "jane", "jane@", "@acme.com", "jane@com", "jane@co.uk", "jane@api.com", "jane@acme_corp.com", "jane@[127.0.0.1]", "a@b@acme.com"} {
		if got, err := SlugFromEmail(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
