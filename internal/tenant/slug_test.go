package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

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

func TestLookup(t *testing.T) {
	ctx := context.Background()
	acme := store.Tenant{ID: "t-acme", Slug: "acme"}
	platform := store.Tenant{ID: "t-platform", Slug: "platform"}
	bySlug := func(_ context.Context, slug string) (store.Tenant, error) {
		if slug == "acme" {
			return acme, nil
		}
		return store.Tenant{}, store.ErrNotFound
	}
	sole := func(context.Context) (store.Tenant, error) { return platform, nil }
	none := func(context.Context) (store.Tenant, error) { return store.Tenant{}, store.ErrNotFound }
	for name, c := range map[string]struct {
		given, email string
		sole         func(context.Context) (store.Tenant, error)
		want         string
		err          error
	}{
		"given slug":                      {given: "acme", email: "jane@jobs.bg", sole: sole, want: "t-acme"},
		"given unknown slug, no fallback": {given: "nope", email: "jane@jobs.bg", sole: sole, err: store.ErrNotFound},
		"given bad slug":                  {given: "Not Valid", email: "jane@acme.com", sole: sole, err: ErrBadSlug},
		"from email domain":               {email: "jane@acme.com", sole: sole, want: "t-acme"},
		"domain unknown, sole tenant":     {email: "jane@jobs.bg", sole: sole, want: "t-platform"},
		"underivable, sole tenant":        {email: "jane", sole: sole, want: "t-platform"},
		"domain unknown, not single":      {email: "jane@jobs.bg", sole: none, err: store.ErrNotFound},
	} {
		got, err := Lookup(ctx, c.given, c.email, bySlug, c.sole)
		if !errors.Is(err, c.err) || got.ID != c.want {
			t.Errorf("%s: %q, %v (want %q, %v)", name, got.ID, err, c.want, c.err)
		}
	}
	// A store failure on the derived slug is not masked by the fallback.
	boom := errors.New("db down")
	failing := func(context.Context, string) (store.Tenant, error) { return store.Tenant{}, boom }
	if _, err := Lookup(ctx, "", "jane@acme.com", failing, sole); !errors.Is(err, boom) {
		t.Errorf("store error: %v", err)
	}
}
