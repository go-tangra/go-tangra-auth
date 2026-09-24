package fuzz

// Fuzz targets for the ldapdir LDAP boundary (spec 016-auth-ldap-import,
// research D5–D8). Every target is seeded from the shared corpus in
// testdata/ldap and asserts the invariants the table suites in
// internal/ldapdir pin:
//
//   - FuzzCompileUserFilter — accepted filters have a byte-stable canonical
//     form within the length cap; refusals stay in the closed vocabulary.
//   - FuzzCombine — the effective filter is a root AND whose first child is
//     the connection's base filter, so no user-typed input can widen the
//     search (SR-003).
//   - FuzzScopeBase — a narrowed base stays DN-equal to the request and
//     within the connection base; refusals never echo the input.
//   - FuzzCheckURL — accepted URLs are ldap(s) endpoints on allowed ports.
//   - FuzzDecodeEntry — hostile GUIDs/values/e-mails never panic, fit the
//     per-value caps and decode deterministically.
//
// The targets compile against ldapdir filter.go/dn.go/mapping.go (T044–T046);
// like the rest of the tests-first ldapdir surface they do not build until
// those land.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/config"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
)

// ldapCorpus returns the contents of every file in testdata/ldap/sub in
// sorted file-name order. Files hold their exact bytes — no trailing
// newline — including the non-UTF-8 .bin fixtures.
func ldapCorpus(f *testing.F, sub string) []string {
	f.Helper()
	dir := filepath.Join("testdata", "ldap", sub)
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("read corpus dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatalf("read corpus file %s: %v", e.Name(), err)
		}
		out = append(out, string(b))
	}
	return out
}

func FuzzCompileUserFilter(f *testing.F) {
	for _, s := range ldapCorpus(f, "filters") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ldapdir.CompileUserFilter(s)
		if err != nil {
			if got != (ldapdir.Filter{}) {
				t.Fatalf("refused filter %.80q returned non-zero Filter %q", s, got.String())
			}
			if !errors.Is(err, ldapdir.ErrInvalidFilter) {
				t.Fatalf("CompileUserFilter(%.80q) error %v is not ErrInvalidFilter", s, err)
			}
			return
		}
		if len(got.String()) > ldapdir.MaxFilterBytes {
			t.Fatalf("canonical form of accepted %.80q is %d bytes, over MaxFilterBytes", s, len(got.String()))
		}
		again, err := ldapdir.CompileUserFilter(got.String())
		if err != nil {
			t.Fatalf("canonical filter %q (accepted from %.80q) does not re-compile: %v", got.String(), s, err)
		}
		if again != got {
			t.Fatalf("canonical form is not a fixed point: %q re-compiles to %q", got.String(), again.String())
		}
	})
}

// combineBases seeds the connection half of FuzzCombine; the corpus strings
// are the user half.
var combineBases = []string{
	"",
	"(objectClass=*)",
	"(objectClass=person)",
	"(|(ou=Eng)(ou=Ops))",
	"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
}

func FuzzCombine(f *testing.F) {
	for _, base := range combineBases {
		for _, user := range ldapCorpus(f, "filters") {
			f.Add(base, user)
		}
	}
	f.Fuzz(func(t *testing.T, base, user string) {
		bf, err := ldapdir.CompileUserFilter(base)
		if err != nil {
			return
		}
		uf, err := ldapdir.CompileUserFilter(user)
		if err != nil {
			return
		}
		combined, err := ldapdir.Combine(bf, uf)
		if err != nil {
			t.Fatalf("Combine(%q, %q): %v (combining two accepted filters must succeed)", bf.String(), uf.String(), err)
		}
		assertRootAnd(t, combined, bf, uf)
	})
}

// assertRootAnd asserts the combination invariant on the compiled BER
// packet: a root AND with exactly two children, the base filter first and
// the user filter second (mirrors the table suite in
// internal/ldapdir/filter_test.go).
func assertRootAnd(t *testing.T, combined, base, user ldapdir.Filter) {
	t.Helper()
	if want := "(&" + base.String() + user.String() + ")"; combined.String() != want {
		t.Fatalf("Combine(%q, %q) = %q, want %q", base.String(), user.String(), combined.String(), want)
	}
	pkt, err := ldap.CompileFilter(combined.String())
	if err != nil {
		t.Fatalf("combined filter %q does not compile: %v", combined.String(), err)
	}
	if pkt.ClassType != ber.ClassContext || pkt.Tag != ldap.FilterAnd {
		t.Fatalf("combined filter %q root is class %d tag %d, want a context AND", combined.String(), pkt.ClassType, pkt.Tag)
	}
	if len(pkt.Children) != 2 {
		t.Fatalf("combined filter %q root has %d children, want 2", combined.String(), len(pkt.Children))
	}
	if first, err := ldap.DecompileFilter(pkt.Children[0]); err != nil || first != base.String() {
		t.Fatalf("combined filter %q first child = %q (%v), want base %q", combined.String(), first, err, base.String())
	}
	if second, err := ldap.DecompileFilter(pkt.Children[1]); err != nil || second != user.String() {
		t.Fatalf("combined filter %q second child = %q (%v), want user %q", combined.String(), second, err, user.String())
	}
}

// scopeConnBases seeds the connection base of FuzzScopeBase; the corpus DNs
// are the requested base.
var scopeConnBases = []string{
	"ou=Eng,dc=example,dc=test",
	"dc=example,dc=test",
	"ou=Eng+l=Sofia,dc=example,dc=test",
}

func FuzzScopeBase(f *testing.F) {
	for _, dn := range ldapCorpus(f, "dns") {
		for _, connBase := range scopeConnBases {
			f.Add(connBase, dn)
		}
	}
	f.Fuzz(func(t *testing.T, connBase, requested string) {
		got, err := ldapdir.ScopeBase(connBase, requested)
		if err != nil {
			if got != "" {
				t.Fatalf("ScopeBase(%q, %q) returned %q alongside error %v", connBase, requested, got, err)
			}
			if !errors.Is(err, ldapdir.ErrInvalidBase) {
				t.Fatalf("ScopeBase(%q, %.80q) error %v is not ErrInvalidBase", connBase, requested, err)
			}
			if len(requested) >= 24 && strings.Contains(err.Error(), requested) {
				t.Fatalf("ScopeBase error %q echoes the requested base", err)
			}
			return
		}
		if !ldapdir.WithinBase(connBase, got) {
			t.Fatalf("ScopeBase(%q, %q) = %q, which is not WithinBase the connection base", connBase, requested, got)
		}
		want := requested
		if strings.TrimSpace(requested) == "" {
			want = connBase
		}
		if !sameDNFold(got, want) {
			t.Fatalf("ScopeBase(%q, %q) = %q, want a DN equal to %q", connBase, requested, got, want)
		}
	})
}

// sameDNFold reports whether a and b parse and are the same DN
// (case-insensitive, RFC 4517 distinguishedNameMatch).
func sameDNFold(a, b string) bool {
	pa, err := ldap.ParseDN(a)
	if err != nil {
		return false
	}
	pb, err := ldap.ParseDN(b)
	if err != nil {
		return false
	}
	return pa.EqualFold(pb)
}

func FuzzCheckURL(f *testing.F) {
	pol, err := ldapdir.NewTargetPolicy(config.DirectoryTargets{
		DenyCIDRs:    []string{"10.0.0.0/8"},
		AllowCIDRs:   []string{"10.1.2.0/24"},
		AllowedPorts: []int{389, 636, 3268, 3269},
	})
	if err != nil {
		f.Fatalf("NewTargetPolicy: %v", err)
	}
	for _, raw := range ldapCorpus(f, "urls") {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ep, err := pol.CheckURL(raw)
		if err != nil {
			if !errors.Is(err, ldapdir.ErrInvalidURL) && !errors.Is(err, ldapdir.ErrTargetRefused) {
				t.Fatalf("CheckURL(%.80q) error %v is outside the closed vocabulary", raw, err)
			}
			return
		}
		if ep.Scheme != "ldap" && ep.Scheme != "ldaps" {
			t.Fatalf("CheckURL(%q) accepted scheme %q", raw, ep.Scheme)
		}
		if ep.Host == "" {
			t.Fatalf("CheckURL(%q) accepted an empty host", raw)
		}
		switch ep.Port {
		case 389, 636, 3268, 3269:
		default:
			t.Fatalf("CheckURL(%q) accepted port %d outside the policy", raw, ep.Port)
		}
	})
}

var (
	decodeKinds = []string{"active_directory", "openldap", "other", "bogus"}
	decodeDNs   = []string{
		"",
		"uid=jdoe,ou=people,dc=example,dc=test",
		"CN=John Doe,OU=People,DC=example,DC=test",
	}
	decodeValues = []string{
		"",
		"jdoe@example.test",
		"JDoe@Example.test",
		"John Doe",
		"no-at-sign",
		strings.Repeat("x", 300),
	}
)

func FuzzDecodeEntry(f *testing.F) {
	i := 0
	for _, guid := range ldapCorpus(f, "objectguid") {
		f.Add(
			decodeKinds[i%len(decodeKinds)],
			decodeDNs[i%len(decodeDNs)],
			[]byte(guid),
			decodeValues[i%len(decodeValues)],
			"John Doe", "John", "Doe",
			i%2 == 0,
		)
		i++
	}
	f.Fuzz(func(t *testing.T, kind, dn string, uid []byte, email, display, first, last string, multi bool) {
		m := ldapdir.DefaultMapping(kind)
		attrs := map[string][][]byte{}
		put := func(name string, vals ...[]byte) {
			if name == "" {
				return // attribute not mapped for this kind
			}
			attrs[strings.ToLower(name)] = vals
		}
		uidVals := [][]byte{uid}
		if multi {
			uidVals = append(uidVals, uid)
		}
		put(m.UID, uidVals...)
		put(m.Email, []byte(email))
		put(m.DisplayName, []byte(display))
		put(m.FirstName, []byte(first))
		put(m.LastName, []byte(last))
		e := ldapdir.RawEntry{DN: dn, Attrs: attrs}

		p, err := ldapdir.Decode(m, e)
		if err != nil {
			return
		}
		// Per-value caps after decoding (research D7).
		if len(p.UID) > 256 {
			t.Fatalf("UID is %d bytes, want ≤ 256", len(p.UID))
		}
		if p.DN != dn || len(p.DN) > 1024 {
			t.Fatalf("DN = %q (entry DN %q), want it verbatim within 1024 bytes", p.DN, dn)
		}
		if len(p.Email) > 254 {
			t.Fatalf("email is %d bytes, want ≤ 254", len(p.Email))
		}
		if p.DisplayNameExplicit && len(p.DisplayName) > 100 {
			t.Fatalf("explicit display name is %d bytes, want ≤ 100", len(p.DisplayName))
		}
		if len(p.FirstName) > 100 || len(p.LastName) > 100 {
			t.Fatalf("names over the 100-byte cap: %+v", p)
		}
		if again, err2 := ldapdir.Decode(m, e); err2 != nil || again != p {
			t.Fatalf("Decode not deterministic: first (%+v, %v), then (%+v, %v)", p, err, again, err2)
		}
	})
}
