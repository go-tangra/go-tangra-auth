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
