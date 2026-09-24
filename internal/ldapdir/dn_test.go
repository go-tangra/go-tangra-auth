package ldapdir

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// connBase is the connection base DN used throughout (research D6).
const connBase = "ou=Eng,dc=example,dc=test"

// sameDN reports whether two DN strings parse to the same DN (RFC 4517
// distinguishedNameMatch, case-insensitive). ScopeBase may return a
// canonicalised form, so its result is compared structurally, not byte-wise.
func sameDN(t *testing.T, a, b string) bool {
	t.Helper()
	pa, err := ldap.ParseDN(a)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", a, err)
	}
	pb, err := ldap.ParseDN(b)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", b, err)
	}
	return pa.EqualFold(pb)
}

// invalidDNs never parse to a usable DN: empty, blank, not a DN, dangling
// separators, a missing type, an empty value, a dangling escape, a bad hex
// escape and a DN over the 1024-byte cap.
var invalidDNs = []string{
	"",
	"   ",
	"garbage",
	"example.test",
	"ou=Eng,",
	",ou=Eng,dc=example,dc=test",
	"=Eng,dc=example,dc=test",
	"cn=,ou=Eng,dc=example,dc=test",
	"cn=x+,ou=Eng,dc=example,dc=test",
	`cn=x\,ou=Eng,dc=example,dc=test\`,
	`cn=\zz,ou=Eng,dc=example,dc=test`,
	"cn=" + strings.Repeat("a", 1100) + "," + connBase,
}

func TestScopeBaseAccepted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, conn, requested string
	}{
		{"equal", connBase, connBase},
		{"equal different case", connBase, "OU=eng,DC=Example,DC=TEST"},
		{"equal with spaces around separators", connBase, "ou=Eng, dc=example, dc=test"},
		{"equal hex-escaped value", connBase, `ou=\45ng,dc=example,dc=test`},
		{"child", connBase, "ou=People," + connBase},
		{"grandchild", connBase, "ou=Sofia,ou=People," + connBase},
		{"descendant different case", connBase, "OU=People,OU=ENG,DC=EXAMPLE,DC=test"},
		{"escaped comma in child value", connBase, `cn=Doe\, John,` + connBase},
		{"escaped comma quoted-hex form", connBase, `cn=Doe\2C John,` + connBase},
		{"multi-valued child RDN", connBase, "cn=John+uid=jdoe," + connBase},
		{"multi-valued base, same order", "ou=Eng+l=Sofia,dc=example,dc=test", "ou=People,ou=Eng+l=Sofia,dc=example,dc=test"},
		{"multi-valued base, swapped order", "ou=Eng+l=Sofia,dc=example,dc=test", "ou=People,l=sofia+OU=eng,dc=example,dc=test"},
		{"multi-valued base equal swapped", "ou=Eng+l=Sofia,dc=example,dc=test", "l=Sofia+ou=Eng,dc=example,dc=test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ScopeBase(tc.conn, tc.requested)
			if err != nil {
				t.Fatalf("ScopeBase(%q, %q) error = %v, want nil", tc.conn, tc.requested, err)
			}
			if !sameDN(t, got, tc.requested) {
				t.Fatalf("ScopeBase(%q, %q) = %q, want a DN equal to the requested base", tc.conn, tc.requested, got)
			}
			if !WithinBase(tc.conn, got) {
				t.Fatalf("ScopeBase result %q is not WithinBase(%q)", got, tc.conn)
			}
		})
	}
}

// An empty (or blank) requested base means "no narrowing": the search runs at
// the connection base.
func TestScopeBaseEmptyRequestedUsesConnectionBase(t *testing.T) {
	t.Parallel()
	for _, requested := range []string{"", "   "} {
		got, err := ScopeBase(connBase, requested)
		if err != nil {
			t.Fatalf("ScopeBase(%q, %q) error = %v, want nil", connBase, requested, err)
		}
		if !sameDN(t, got, connBase) {
			t.Fatalf("ScopeBase(%q, %q) = %q, want the connection base", connBase, requested, got)
		}
	}
}

func TestScopeBaseRefused(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, conn, requested string
	}{
		{"parent of base", connBase, "dc=example,dc=test"},
		{"root of tree", connBase, "dc=test"},
		{"sibling OU", connBase, "ou=Sales,dc=example,dc=test"},
		{"sibling OU child", connBase, "cn=x,ou=Sales,dc=example,dc=test"},
		{"unrelated tree", connBase, "ou=Eng,dc=other,dc=test"},
		// String-suffix tricks: each ends with the base's text but is not
		// under it in the DN tree.
		{"sibling-suffix domain", "dc=example,dc=test", "dc=evilexample,dc=test"},
		{"sibling-suffix domain child", "dc=example,dc=test", "ou=Eng,dc=evilexample,dc=test"},
		{"sibling-suffix OU", connBase, "ou=Eng,dc=evilexample,dc=test"},
		{"sibling-suffix OU value", connBase, "ou=BigEng,dc=example,dc=test"},
		{"sibling-suffix OU value child", connBase, "cn=x,ou=BigEng,dc=example,dc=test"},
		// Escaped commas: one RDN whose value merely contains the base text.
		{"escaped comma swallows base RDN", "dc=example,dc=test", `ou=Eng\,dc=example,dc=test`},
		{"escaped comma swallows whole base", connBase, `cn=x\,ou=Eng\,dc=example\,dc=test`},
		{"hex-escaped comma swallows base RDN", "dc=example,dc=test", `ou=Eng\2Cdc=example,dc=test`},
		// Multi-valued RDNs must match as a whole, not as a subset.
		{"base RDN is subset of multi-valued RDN", connBase, "cn=x,ou=Eng+l=Sofia,dc=example,dc=test"},
		{"multi-valued base, single-valued request", "ou=Eng+l=Sofia,dc=example,dc=test", "cn=x," + connBase},
		{"multi-valued base, different value", "ou=Eng+l=Sofia,dc=example,dc=test", "cn=x,ou=Eng+l=Varna,dc=example,dc=test"},
		// Case folding is for matching only; a different value is still outside.
		{"different value same letters", connBase, "ou=Engx,dc=example,dc=test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ScopeBase(tc.conn, tc.requested)
			if !errors.Is(err, ErrInvalidBase) {
				t.Fatalf("ScopeBase(%q, %q) = (%q, %v), want ErrInvalidBase", tc.conn, tc.requested, got, err)
			}
			if got != "" {
				t.Fatalf("ScopeBase(%q, %q) returned %q alongside an error, want \"\"", tc.conn, tc.requested, got)
			}
		})
	}
}

func TestScopeBaseInvalidRequested(t *testing.T) {
	t.Parallel()
	for _, requested := range invalidDNs {
		if strings.TrimSpace(requested) == "" {
			continue // blank means "use the connection base"
		}
		got, err := ScopeBase(connBase, requested)
		if !errors.Is(err, ErrInvalidBase) {
			t.Errorf("ScopeBase(%q, %.60q) = (%q, %v), want ErrInvalidBase", connBase, requested, got, err)
		}
		if got != "" {
			t.Errorf("ScopeBase(%q, %.60q) returned %q alongside an error", connBase, requested, got)
		}
	}
}

func TestScopeBaseInvalidConnectionBase(t *testing.T) {
	t.Parallel()
	for _, conn := range invalidDNs {
		for _, requested := range []string{"", connBase, "ou=People," + connBase} {
			got, err := ScopeBase(conn, requested)
			if !errors.Is(err, ErrInvalidBase) {
				t.Errorf("ScopeBase(%.60q, %q) = (%q, %v), want ErrInvalidBase", conn, requested, got, err)
			}
		}
	}
}

// The error text must not echo the caller's input (it may be logged).
func TestScopeBaseErrorDoesNotEchoInput(t *testing.T) {
	t.Parallel()
	const marker = "SECRETMARKERVALUE"
	for _, requested := range []string{
		"ou=" + marker + ",dc=evilexample,dc=test",
		"cn=" + marker + "\\",
	} {
		_, err := ScopeBase(connBase, requested)
		if err == nil {
			t.Fatalf("ScopeBase(%q) error = nil, want ErrInvalidBase", requested)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("ScopeBase error %q echoes the requested base", err)
		}
	}
}

func TestWithinBase(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, conn, entry string
		want              bool
	}{
		{"base entry itself", connBase, connBase, true},
		{"base entry different case", connBase, "OU=ENG,DC=EXAMPLE,DC=TEST", true},
		{"direct child", connBase, "uid=jdoe," + connBase, true},
		{"deep descendant", connBase, "uid=jdoe,ou=People,ou=Sofia," + connBase, true},
		{"descendant with spaces", connBase, "uid=jdoe, ou=Eng, dc=example, dc=test", true},
		{"descendant different case", connBase, "UID=JDoe,OU=eng,dc=Example,DC=test", true},
		{"escaped comma in entry value", connBase, `cn=Doe\, John,` + connBase, true},
		{"multi-valued entry RDN", connBase, "cn=John Doe+uid=jdoe," + connBase, true},
		{"multi-valued base, swapped order", "ou=Eng+l=Sofia,dc=example,dc=test", "uid=j,L=SOFIA+ou=eng,dc=example,dc=test", true},

		{"parent", connBase, "dc=example,dc=test", false},
		{"sibling", connBase, "uid=jdoe,ou=Sales,dc=example,dc=test", false},
		{"alias target outside", connBase, "uid=admin,ou=Admins,dc=example,dc=test", false},
		{"other tree", connBase, "uid=jdoe,ou=Eng,dc=other,dc=test", false},
		{"sibling-suffix domain", "dc=example,dc=test", "uid=jdoe,dc=evilexample,dc=test", false},
		{"sibling-suffix OU", connBase, "uid=jdoe,ou=Eng,dc=evilexample,dc=test", false},
		{"sibling-suffix OU value", connBase, "uid=jdoe,ou=BigEng,dc=example,dc=test", false},
		{"escaped comma swallows base", connBase, `uid=jdoe\,ou=Eng\,dc=example\,dc=test`, false},
		{"escaped comma swallows base RDN", "dc=example,dc=test", `uid=jdoe,ou=Eng\,dc=example,dc=test`, false},
		{"base RDN subset of multi-valued RDN", connBase, "uid=jdoe,ou=Eng+l=Sofia,dc=example,dc=test", false},
		{"multi-valued base, single-valued entry", "ou=Eng+l=Sofia,dc=example,dc=test", "uid=jdoe," + connBase, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := WithinBase(tc.conn, tc.entry); got != tc.want {
				t.Fatalf("WithinBase(%q, %q) = %v, want %v", tc.conn, tc.entry, got, tc.want)
			}
		})
	}
}

// Anything unparseable — on either side — is never within the base.
func TestWithinBaseInvalid(t *testing.T) {
	t.Parallel()
	for _, dn := range invalidDNs {
		if WithinBase(connBase, dn) {
			t.Errorf("WithinBase(%q, %.60q) = true for an invalid entry DN", connBase, dn)
		}
		if WithinBase(dn, "uid=jdoe,"+connBase) {
			t.Errorf("WithinBase(%.60q, entry) = true for an invalid connection base", dn)
		}
		if WithinBase(dn, dn) {
			t.Errorf("WithinBase(%.60q, same) = true for an invalid DN", dn)
		}
	}
}
