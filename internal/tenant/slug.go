package tenant

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// reserved slugs collide with routes or platform names and are refused.
var reserved = map[string]struct{}{"api": {}, "www": {}, "admin": {}, "operator": {}, "auth": {}, "static": {}, "assets": {}, "login": {}}

// ErrBadSlug is returned for tenant slugs outside the grammar.
var ErrBadSlug = errors.New("tenant: invalid slug")

// ParseSlug validates a tenant slug (1–63 chars, [a-z0-9-], DNS-label shape, not reserved).
func ParseSlug(s string) (string, error) {
	if !slugRE.MatchString(s) {
		return "", ErrBadSlug
	}
	if _, ok := reserved[s]; ok {
		return "", ErrBadSlug
	}
	return s, nil
}

// SlugFromEmail derives the tenant slug from an e-mail address when the user
// signs in without naming a tenant: the registrable domain's organisation
// label, public-suffix aware (jane@mail.acme.co.uk → "acme"). The result must
// still be a valid, non-reserved slug; anything else is ErrBadSlug.
func SlugFromEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') {
		return "", ErrBadSlug
	}
	domain := strings.TrimSuffix(email[at+1:], ".")
	if domain == "" || strings.ContainsAny(domain, "[]:") {
		return "", ErrBadSlug
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", ErrBadSlug
	}
	label, _, _ := strings.Cut(reg, ".")
	return ParseSlug(label)
}

// Lookup resolves the tenant a sign-in or recovery request names. A given
// slug is used as is. With none given, the slug comes from the e-mail domain
// (SlugFromEmail); when that names no tenant, a deployment with exactly one
// tenant falls back to it, so its users need not know the slug.
func Lookup(ctx context.Context, given, email string, bySlug func(context.Context, string) (store.Tenant, error), sole func(context.Context) (store.Tenant, error)) (store.Tenant, error) {
	if strings.TrimSpace(given) != "" {
		slug, err := ParseSlug(given)
		if err != nil {
			return store.Tenant{}, err
		}
		return bySlug(ctx, slug)
	}
	if slug, err := SlugFromEmail(email); err == nil {
		if t, err := bySlug(ctx, slug); !errors.Is(err, store.ErrNotFound) {
			return t, err
		}
	}
	return sole(ctx)
}
