package ldapdir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Filter validation and combination (research D6, SR-003, SC-005).
//
// Everything here is pure: CompileUserFilter and Combine take no context and
// no Directory, so an invalid filter is refused before any network call can
// exist. The shape the tests pin down for T044:
//
//	type Filter struct{ /* unexported canonical form */ }
//	func (Filter) String() string          // canonical RFC 4515 text
//	func CompileUserFilter(s string) (Filter, error)
//	func Combine(base, user Filter) (Filter, error)
//	type FilterError struct{ Detail string } // Is(ErrInvalidFilter)
//
// Caps, counted on the compiled filter tree:
//   - length: input ≤ MaxFilterBytes (4096) and canonical output ≤ 4096
//     (the canonical form is what gets stored and sent);
//   - depth: filter elements on the longest root-to-leaf path, leaf included,
//     ≤ 16 — so fifteen nested (&…) around a leaf is the deepest accepted;
//   - components: every filter element (and/or/not nodes and leaves) ≤ 64.
//
// Caps apply to each half; Combine of two accepted filters always succeeds.

const fltCorpusDir = "../../tests/fuzz/testdata/ldap/filters"

// fltCorpus returns the corpus files whose name starts with prefix, keyed by
// file name, in sorted order.
func fltCorpus(t *testing.T, prefix string) (names []string, inputs map[string]string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(fltCorpusDir, prefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no corpus files %s* under %s", prefix, fltCorpusDir)
	}
	sort.Strings(paths)
	inputs = make(map[string]string, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed test corpus
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(p)
		names = append(names, name)
		inputs[name] = string(b)
	}
	return names, inputs
}

func fltMust(t *testing.T, s string) Filter {
	t.Helper()
	f, err := CompileUserFilter(s)
	if err != nil {
		t.Fatalf("CompileUserFilter(%.80q): %v", s, err)
	}
	return f
}

// fltRefused asserts err is a filter refusal in the closed vocabulary and
// returns its detail.
func fltRefused(t *testing.T, input string, f Filter, err error) string {
	t.Helper()
	if err == nil {
		t.Fatalf("CompileUserFilter(%.80q) = %q, want ErrInvalidFilter", input, f.String())
	}
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("CompileUserFilter(%.80q) error = %v, want errors.Is ErrInvalidFilter", input, err)
	}
	if got := Reason(err); got != "invalid_filter" {
		t.Fatalf("Reason(%v) = %q, want invalid_filter", err, got)
	}
	if !errors.Is(mapError(err), ErrInvalidFilter) {
		t.Fatalf("mapError(%v) left the closed vocabulary", err)
	}
	if f != (Filter{}) {
		t.Fatalf("refused filter %.80q returned non-zero Filter %q", input, f.String())
	}
	var fe *FilterError
	if !errors.As(err, &fe) {
		t.Fatalf("error %T is not a *FilterError", err)
	}
	if fe.Detail == "" {
		t.Fatalf("FilterError for %.80q has an empty Detail", input)
	}
	if !utf8.ValidString(fe.Detail) || strings.IndexFunc(fe.Detail, unicode.IsControl) >= 0 {
		t.Fatalf("FilterError.Detail %q must be valid UTF-8 without control characters", fe.Detail)
	}
	if strings.Contains(err.Error(), "LDAP Result Code") {
		t.Fatalf("error %q leaks the go-ldap result-code wrapper", err)
	}
	if !strings.Contains(err.Error(), fe.Detail) {
		t.Fatalf("Error() %q does not carry Detail %q", err, fe.Detail)
	}
	return fe.Detail
}

// parserDetail is the go-ldap parser's own message for s, without the
// "LDAP Result Code 201" wrapper and the "ldap: " prefix.
func parserDetail(t *testing.T, s string) string {
	t.Helper()
	_, err := ldap.CompileFilter(s)
	if err == nil {
		t.Fatalf("ldap.CompileFilter(%q) accepted a grammar-invalid fixture", s)
	}
	var le *ldap.Error
	if !errors.As(err, &le) || le.Err == nil {
		t.Fatalf("ldap.CompileFilter(%q) error %T has no inner message", s, err)
	}
	return strings.TrimPrefix(le.Err.Error(), "ldap: ")
}

// libCanonical is go-ldap's own compile/decompile round trip.
func libCanonical(t *testing.T, s string) string {
	t.Helper()
	p, err := ldap.CompileFilter(s)
	if err != nil {
		t.Fatalf("ldap.CompileFilter(%q): %v", s, err)
	}
	out, err := ldap.DecompileFilter(p)
	if err != nil {
		t.Fatalf("ldap.DecompileFilter(%q): %v", s, err)
	}
	return out
}

// nestAnd wraps leaf in n levels of (&…).
func nestAnd(n int, leaf string) string {
	return strings.Repeat("(&", n) + leaf + strings.Repeat(")", n)
}

// orOf is an (|…) with n equality leaves: n+1 components.
func orOf(n int) string {
	var b strings.Builder
	b.WriteString("(|")
	for i := range n {
		fmt.Fprintf(&b, "(uid=u%02d)", i)
	}
	b.WriteString(")")
	return b.String()
}

func TestCompileUserFilterAcceptsValidCorpus(t *testing.T) {
	names, inputs := fltCorpus(t, "valid-")
	for _, name := range names {
		in := inputs[name]
		t.Run(name, func(t *testing.T) {
			f := fltMust(t, in)
			want := "(objectClass=*)"
			if in != "" {
				want = libCanonical(t, in)
			}
			if f.String() != want {
				t.Fatalf("CompileUserFilter(%q) = %q, want canonical %q", in, f.String(), want)
			}
		})
	}
}

func TestCompileUserFilterEmptyMatchesEverything(t *testing.T) {
	for _, in := range []string{"", " ", "\t", " \t\r\n "} {
		f := fltMust(t, in)
		if f.String() != "(objectClass=*)" {
			t.Fatalf("CompileUserFilter(%q) = %q, want (objectClass=*)", in, f.String())
		}
	}
}

func TestCompileUserFilterRefusesGrammarErrors(t *testing.T) {
	names, inputs := fltCorpus(t, "invalid-")
	injNames, injInputs := fltCorpus(t, "injection-")
	names = append(names, injNames...)
	for k, v := range injInputs {
		inputs[k] = v
	}
	// Extra shapes the corpus does not cover.
	extra := map[string]string{
		"extra-after-filter": "(uid=a)b",
		"bad-escape":         `(uid=a\zz)`,
		"short-escape":       `(uid=a\2)`,
		"leading-space":      " (uid=a)",
		"only-close-parens":  "))))",
	}
	for k, v := range extra {
		names = append(names, k)
		inputs[k] = v
	}
	for _, name := range names {
		in := inputs[name]
		t.Run(name, func(t *testing.T) {
			f, err := CompileUserFilter(in)
			detail := fltRefused(t, in, f, err)
			if !utf8.ValidString(in) {
				return // refused by the UTF-8 check before the parser runs
			}
			// The admin sees the parser's own position message; it only ever
			// quotes what they typed.
			if want := parserDetail(t, in); detail != want {
				t.Fatalf("Detail = %q, want parser message %q", detail, want)
			}
		})
	}
}

func TestCompileUserFilterRefusesPolicyCorpus(t *testing.T) {
	names, inputs := fltCorpus(t, "policy-")
	for _, name := range names {
		in := inputs[name]
		t.Run(name, func(t *testing.T) {
			// Corpus contract: the grammar accepts it, only freya policy refuses it.
			if _, err := ldap.CompileFilter(in); err != nil {
				t.Fatalf("fixture is not grammar-valid: %v", err)
			}
			f, err := CompileUserFilter(in)
			detail := fltRefused(t, in, f, err)
			if len(in) > 64 && strings.Contains(detail, in) {
				t.Fatalf("policy Detail echoes the whole input")
			}
		})
	}
}

func TestCompileUserFilterOddCorpusNeverPanics(t *testing.T) {
	names, inputs := fltCorpus(t, "odd-")
	for _, name := range names {
		f, err := CompileUserFilter(inputs[name])
		if err != nil {
			fltRefused(t, inputs[name], f, err)
			continue
		}
		if again := fltMust(t, f.String()); again != f {
			t.Fatalf("%s: canonical %q is not stable (%q)", name, f.String(), again.String())
		}
	}
}

func TestCompileUserFilterLengthCap(t *testing.T) {
	if MaxFilterBytes != 4096 {
		t.Fatalf("MaxFilterBytes = %d, want 4096 (contract base_filter/filter ≤ 4096)", MaxFilterBytes)
	}
	pad := func(n int) string { return "(uid=" + strings.Repeat("a", n-len("(uid=)")) + ")" }

	atCap := pad(MaxFilterBytes)
	if len(atCap) != MaxFilterBytes {
		t.Fatalf("fixture length %d", len(atCap))
	}
	if f := fltMust(t, atCap); f.String() != atCap {
		t.Fatalf("filter at the cap was rewritten")
	}

	over := pad(MaxFilterBytes + 1)
	f, err := CompileUserFilter(over)
	fltRefused(t, over, f, err)

	// Canonical output is what is stored and sent, so it is capped too:
	// each "ü" (2 bytes) re-serialises as \c3\bc (6 bytes).
	expands := "(cn=" + strings.Repeat("ü", 1000) + ")"
	if len(expands) > MaxFilterBytes || len(libCanonical(t, expands)) <= MaxFilterBytes {
		t.Fatalf("fixture does not straddle the cap")
	}
	f, err = CompileUserFilter(expands)
	fltRefused(t, expands, f, err)
}

func TestCompileUserFilterRefusesBadBytes(t *testing.T) {
	for name, in := range map[string]string{
		"invalid-utf8-value": "(cn=\xff)",
		"invalid-utf8-attr":  "(\xc3=x)",
		"truncated-rune":     "(cn=J\xc3)",
		"raw-nul":            "(uid=a\x00)",
		"escaped-nul":        `(uid=\00)`,
		"escaped-nul-substr": `(uid=*\00*)`,
		"escaped-nul-ext":    `(cn:caseExactMatch:=\00)`,
		"escaped-nul-in-and": `(&(objectClass=person)(uid=a\00b))`,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := CompileUserFilter(in)
			fltRefused(t, in, f, err)
		})
	}
}

func TestCompileUserFilterDepthCap(t *testing.T) {
	leaf := "(objectClass=*)"
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"leaf-only", leaf, true},
		{"and-15-deep-16", nestAnd(15, leaf), true},
		{"and-16-deep-17", nestAnd(16, leaf), false},
		{"and-20", nestAnd(20, leaf), false},
		{"not-15", strings.Repeat("(!", 15) + leaf + strings.Repeat(")", 15), true},
		{"not-16", strings.Repeat("(!", 16) + leaf + strings.Repeat(")", 16), false},
		{"mixed-16", strings.Repeat("(|(!", 8) + leaf + strings.Repeat("))", 8), false},
		{"mixed-15", "(&" + strings.Repeat("(|(!", 7) + leaf + strings.Repeat("))", 7) + ")", true},
		// Only the deepest path counts, not the sum over siblings.
		{"wide-shallow", "(&" + nestAnd(14, leaf) + nestAnd(14, leaf) + ")", true},
		{"one-deep-branch", "(&(uid=a)" + nestAnd(15, leaf) + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := CompileUserFilter(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("CompileUserFilter(%q): %v", tc.in, err)
				}
				return
			}
			fltRefused(t, tc.in, f, err)
		})
	}
}

func TestCompileUserFilterComponentCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"or-63-leaves-64", orOf(63), true},
		{"or-64-leaves-65", orOf(64), false},
		{"or-70", orOf(70), false},
		// Inner and/or/not nodes are components too: & ! (uid=x) | + 61 leaves = 65.
		{"nested-inner-nodes-count", "(&(!(uid=x))" + orOf(61) + ")", false},
		{"nested-at-cap", "(&(!(uid=x))" + orOf(60) + ")", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := CompileUserFilter(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("CompileUserFilter(%.80q): %v", tc.in, err)
				}
				return
			}
			fltRefused(t, tc.in, f, err)
		})
	}
}

func TestCompileUserFilterAttributeDescriptions(t *testing.T) {
	good := []string{"uid", "cn", "objectClass", "UID", "x", "sAMAccountName", "user-name", "cn;lang-en", "cn;lang-en;binary", "userCertificate;binary", "1.2.3.4", "2.5.4.3"}
	bad := []string{"bad_attr", "-uid", "1uid", ";x", "cn;", "cn;;x", "cn;lang_en", " uid", "uid ", "u id", "1.2.3.", ".1.2", "1..2", "1.2a", "ü", "cn.x", "uid$"}
	shapes := map[string]string{
		"equality":   "(%s=x)",
		"presence":   "(%s=*)",
		"substrings": "(%s=a*b)",
		"ge":         "(%s>=1)",
		"le":         "(%s<=1)",
		"approx":     "(%s~=x)",
		"extensible": "(%s:caseExactMatch:=x)",
		"nested":     "(&(objectClass=person)(!(%s=x)))",
	}
	for shape, tmpl := range shapes {
		for _, a := range good {
			in := fmt.Sprintf(tmpl, a)
			if _, err := CompileUserFilter(in); err != nil {
				t.Errorf("%s: CompileUserFilter(%q): %v", shape, in, err)
			}
		}
		for _, a := range bad {
			in := fmt.Sprintf(tmpl, a)
			if _, err := ldap.CompileFilter(in); err != nil {
				continue // grammar refusal, covered elsewhere
			}
			f, err := CompileUserFilter(in)
			fltRefused(t, in, f, err)
		}
	}
}

func TestCompileUserFilterExtensibleMatch(t *testing.T) {
	for _, in := range []string{
		"(cn:caseExactMatch:=fred)",
		"(cn:2.5.13.5:=fred)",
		"(cn:=fred)",
		"(:caseExactMatch:=fred)",
		"(:2.5.13.5:=fred)",
		// :dn: also matches DN components (e.g. exclude an OU).
		"(cn:dn:caseExactMatch:=fred)",
		"(cn:dn:=fred)",
		"(o:dn:=Ace)",
		"(:dn:2.4.6.8.10:=Dino)",
		"(&(objectClass=person)(|(uid=a)(ou:dn:=Eng)))",
		"(!(ou:dn:=SystemAccounts))",
		"(&(objectCategory=person)(objectClass=user)(!(ou:dn:=SystemAccounts))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
	} {
		if _, err := CompileUserFilter(in); err != nil {
			t.Errorf("CompileUserFilter(%q): %v", in, err)
		}
	}
	// go-ldap parses a non-lowercase :DN: as a matching rule named DN, which
	// no server knows: refused with a hint instead of failing at the server.
	for _, in := range []string{
		"(cn:DN:=fred)",
		"(cn:Dn:caseExactMatch:=fred)",
		"(!(cn:DN:=x))",
		// Matching rules must be a descriptor or an OID.
		"(cn:bad_rule:=fred)",
		"(cn:1.2.:=fred)",
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := ldap.CompileFilter(in); err != nil {
				t.Fatalf("fixture is not grammar-valid: %v", err)
			}
			f, err := CompileUserFilter(in)
			fltRefused(t, in, f, err)
		})
	}
}

func TestCompileUserFilterCanonicalForm(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"(cn=Jürgen)", `(cn=J\c3\bcrgen)`},
		{`(uid=\41lice)`, "(uid=Alice)"},
		{`(uid=a\2A)`, `(uid=a\2a)`},
		{`(cn=Smith\2c John)`, "(cn=Smith, John)"},
		{`(uid=weird\28paren\29)`, `(uid=weird\28paren\29)`},
		{"(uid=a*l*e)", "(uid=a*l*e)"},
		{"(&(objectClass=person)(uid=alice))", "(&(objectClass=person)(uid=alice))"},
		{"(UID=Alice)", "(UID=Alice)"},
	} {
		f := fltMust(t, tc.in)
		if f.String() != tc.want {
			t.Errorf("CompileUserFilter(%q) = %q, want %q", tc.in, f.String(), tc.want)
		}
	}

	// Canonicalisation is a fixed point for every accepted corpus entry.
	for _, prefix := range []string{"valid-", "odd-"} {
		names, inputs := fltCorpus(t, prefix)
		for _, name := range names {
			f, err := CompileUserFilter(inputs[name])
			if err != nil {
				continue
			}
			again := fltMust(t, f.String())
			if again.String() != f.String() {
				t.Errorf("%s: canonical %q re-compiles to %q", name, f.String(), again.String())
			}
			if again != f {
				t.Errorf("%s: equal canonical strings yield unequal Filters", name)
			}
		}
	}
}

func TestFilterErrorIsClosed(t *testing.T) {
	fe := &FilterError{Detail: "unexpected end of filter"}
	if !errors.Is(fe, ErrInvalidFilter) {
		t.Fatal("FilterError must match ErrInvalidFilter")
	}
	for _, s := range closedSentinels {
		if s != ErrInvalidFilter && errors.Is(fe, s) {
			t.Fatalf("FilterError also matches %v", s)
		}
	}
	if !strings.HasPrefix(fe.Error(), ErrInvalidFilter.Error()) || !strings.Contains(fe.Error(), fe.Detail) {
		t.Fatalf("Error() = %q, want %q prefix with the detail", fe.Error(), ErrInvalidFilter)
	}
	if got := mapError(fe); got != ErrInvalidFilter {
		t.Fatalf("mapError(FilterError) = %v, want bare ErrInvalidFilter", got)
	}

	// Control characters the admin typed never reach the message verbatim.
	in := "(uid=a)\x01\x1b[31mred"
	f, err := CompileUserFilter(in)
	fltRefused(t, in, f, err)
}

func TestFilterZeroValue(t *testing.T) {
	var zero Filter
	if zero.String() != "" {
		t.Fatalf("zero Filter String() = %q, want empty", zero.String())
	}
}

// assertCombined checks the invariant that makes the combination
// injection-proof: the effective filter's root is an AND with exactly two
// children, the first of which is the base filter and the second the user
// filter.
func assertCombined(t *testing.T, base, user, got Filter) {
	t.Helper()
	want := "(&" + base.String() + user.String() + ")"
	if got.String() != want {
		t.Fatalf("Combine(%q, %q) = %q, want %q", base.String(), user.String(), got.String(), want)
	}
	p, err := ldap.CompileFilter(got.String())
	if err != nil {
		t.Fatalf("combined filter %q does not compile: %v", got.String(), err)
	}
	if p.ClassType != ber.ClassContext || p.Tag != ldap.FilterAnd {
		t.Fatalf("combined root %q is not an AND (tag %d)", got.String(), p.Tag)
	}
	if len(p.Children) != 2 {
		t.Fatalf("combined root %q has %d children, want 2", got.String(), len(p.Children))
	}
	first, err := ldap.DecompileFilter(p.Children[0])
	if err != nil || first != base.String() {
		t.Fatalf("combined first child = %q (%v), want base %q", first, err, base.String())
	}
	second, err := ldap.DecompileFilter(p.Children[1])
	if err != nil || second != user.String() {
		t.Fatalf("combined second child = %q (%v), want user %q", second, err, user.String())
	}
}

func TestCombine(t *testing.T) {
	base := fltMust(t, "(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
	user := fltMust(t, "(|(uid=alice)(mail=*@example.org))")
	got, err := Combine(base, user)
	if err != nil {
		t.Fatal(err)
	}
	assertCombined(t, base, user, got)

	// No base filter on the connection: the caller compiles "" and gets the
	// match-all filter, so the root is still (&base user).
	empty := fltMust(t, "")
	got, err = Combine(empty, user)
	if err != nil {
		t.Fatal(err)
	}
	assertCombined(t, empty, user, got)
	got, err = Combine(base, empty)
	if err != nil {
		t.Fatal(err)
	}
	assertCombined(t, base, empty, got)

	// A combination of two accepted filters is always accepted, even when
	// each half sits at the caps.
	deep := fltMust(t, nestAnd(15, "(objectClass=*)"))
	wide := fltMust(t, orOf(63))
	long := fltMust(t, "(uid="+strings.Repeat("a", MaxFilterBytes-len("(uid=)"))+")")
	for _, pair := range [][2]Filter{{deep, deep}, {wide, wide}, {long, long}, {deep, wide}} {
		got, err := Combine(pair[0], pair[1])
		if err != nil {
			t.Fatalf("Combine at caps: %v", err)
		}
		assertCombined(t, pair[0], pair[1], got)
	}
}

func TestCombineRefusesZeroFilters(t *testing.T) {
	ok := fltMust(t, "(uid=a)")
	for _, pair := range [][2]Filter{{{}, ok}, {ok, {}}, {{}, {}}} {
		got, err := Combine(pair[0], pair[1])
		if !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("Combine(%q, %q) error = %v, want ErrInvalidFilter", pair[0].String(), pair[1].String(), err)
		}
		if got != (Filter{}) {
			t.Fatalf("refused Combine returned %q", got.String())
		}
	}
}

// TestCombineInjectionCorpus feeds every corpus string — raw, spliced into a
// value and as a whole filter — through CompileUserFilter; whatever is
// accepted must combine into (&base user) with the base as the first child.
func TestCombineInjectionCorpus(t *testing.T) {
	var fragments []string
	for _, prefix := range []string{"injection-", "invalid-", "valid-", "odd-", "policy-"} {
		names, inputs := fltCorpus(t, prefix)
		for _, n := range names {
			fragments = append(fragments, inputs[n])
		}
	}
	fragments = append(fragments,
		")(|(objectClass=*)", "*)(objectClass=*))(&(uid=*", "))(|(uid=*", ")", "(", "*", `\`, `\2a`, "\x00",
		"a)(!(uid=a", "x)(|(&(objectClass=*))", ")))))))))))))))))(|(uid=*)",
	)
	templates := []string{
		"%s",
		"(uid=%s)",
		"(uid=*%s*)",
		"(&(objectClass=person)(uid=%s))",
		"(|(cn=%s)(mail=%s))",
		"(!(uid=%s))",
		"(cn:caseExactMatch:=%s)",
	}
	bases := []Filter{
		fltMust(t, ""),
		fltMust(t, "(objectClass=person)"),
		fltMust(t, "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
		fltMust(t, "(|(ou=Eng)(ou=Ops))"),
		fltMust(t, "(!(uid=root))"),
	}

	accepted := 0
	check := func(in string) {
		user, err := CompileUserFilter(in)
		if err != nil {
			fltRefused(t, in, user, err)
			return
		}
		accepted++
		for _, base := range bases {
			got, err := Combine(base, user)
			if err != nil {
				t.Fatalf("Combine(%q, %q): %v", base.String(), user.String(), err)
			}
			assertCombined(t, base, user, got)
		}
		// The accepted filter is also a valid base: it must stay first.
		probe := fltMust(t, "(uid=probe)")
		got, err := Combine(user, probe)
		if err != nil {
			t.Fatalf("Combine(%q, probe): %v", user.String(), err)
		}
		assertCombined(t, user, probe, got)
	}
	for _, frag := range fragments {
		for _, tmpl := range templates {
			in := strings.ReplaceAll(tmpl, "%s", frag)
			check(in)
			check(strings.ReplaceAll(tmpl, "%s", ldap.EscapeFilter(frag)))
		}
	}
	if accepted == 0 {
		t.Fatal("no corpus-derived filter was accepted; the invariant was never exercised")
	}

	// Escaped injection strings are always accepted as plain values.
	names, inputs := fltCorpus(t, "injection-")
	for _, n := range names {
		in := "(uid=" + ldap.EscapeFilter(inputs[n]) + ")"
		f := fltMust(t, in)
		p, err := ldap.CompileFilter(f.String())
		if err != nil || p.Tag != ldap.FilterEqualityMatch {
			t.Fatalf("%s: escaped value %q is not a single equality match", n, f.String())
		}
	}
}
