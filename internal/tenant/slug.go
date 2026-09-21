package tenant

import (
	"errors"
	"regexp"
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
