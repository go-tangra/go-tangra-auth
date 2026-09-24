package ldapdir

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// DN scoping (research D6). A search may narrow the connection base but never
// leave it, and every entry the server returns is re-checked against the base
// so an alias, referral or misbehaving server cannot pull in outside entries.
// Comparison is per RDN on parsed DNs (RFC 4517 distinguishedNameMatch, case
// folded), never on strings, so suffix tricks such as dc=evilexample and
// escaped commas that swallow the base text are refused.

// ScopeBase returns the base a search runs at. A blank requested base means no
// narrowing and returns connBase; otherwise requested must equal connBase or be
// a descendant of it and is returned as given. Every failure — an invalid
// connection base, an invalid requested base or one outside the connection
// base — is ErrInvalidBase, whose text never echoes the input.
func ScopeBase(connBase, requested string) (string, error) {
	base, ok := parseDN(connBase)
	if !ok {
		return "", ErrInvalidBase
	}
	if strings.TrimSpace(requested) == "" {
		return connBase, nil
	}
	req, ok := parseDN(requested)
	if !ok || !within(base, req) {
		return "", ErrInvalidBase
	}
	return requested, nil
}

// WithinBase reports whether entryDN is connBase itself or one of its
// descendants. It is false when either DN is invalid.
func WithinBase(connBase, entryDN string) bool {
	base, ok := parseDN(connBase)
	if !ok {
		return false
	}
	entry, ok := parseDN(entryDN)
	return ok && within(base, entry)
}

func within(base, dn *ldap.DN) bool {
	return base.EqualFold(dn) || base.AncestorOfFold(dn)
}

// parseDN parses a DN usable as a base or entry name: non-blank, at most
// MaxDNBytes, at least one RDN, and no RDN with an empty type or value
// (ldap.ParseDN accepts "" and "cn=").
func parseDN(s string) (*ldap.DN, bool) {
	if strings.TrimSpace(s) == "" || len(s) > MaxDNBytes {
		return nil, false
	}
	dn, err := ldap.ParseDN(s)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, false
	}
	for _, rdn := range dn.RDNs {
		for _, a := range rdn.Attributes {
			if a.Type == "" || a.Value == "" {
				return nil, false
			}
		}
	}
	return dn, true
}
