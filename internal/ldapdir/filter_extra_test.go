package ldapdir

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Defensive branches go-ldap never reaches from filter text, driven with
// hand-built packets and filters.

func fxLeaf(tag ber.Tag, attr, value string) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, "")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, ""))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
	return p
}

func fxEmptyAny() *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterSubstrings, nil, "")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", ""))
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ldap.FilterSubstringsAny, "", ""))
	p.AppendChild(seq)
	return p
}

func TestCanonicaliseRefusesUnstablePackets(t *testing.T) {
	for name, p := range map[string]*ber.Packet{
		// Decompile panics on a NOT without a child.
		"not-without-child": ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterNot, nil, ""),
		// "(a\29=x)" re-parses with the literal attribute a\29, which the
		// policy refuses.
		"escaped-attr": fxLeaf(ldap.FilterEqualityMatch, "a)", "x"),
		// "(cn:dn=x)" re-parses as an extensible match with rule "dn=x".
		"reparse-refused": fxLeaf(ldap.FilterEqualityMatch, "cn:dn", "x"),
		// An empty "any" part writes "(cn=**)", which re-parses as "(cn=)".
		"empty-substring": fxEmptyAny(),
	} {
		t.Run(name, func(t *testing.T) {
			if canon, detail := canonicalise(p); detail == "" || canon != "" {
				t.Fatalf("canonicalise = %q, %q; want a refusal", canon, detail)
			}
		})
	}
}

func TestCheckFilterRefusesMalformedPackets(t *testing.T) {
	short := func(tag ber.Tag) *ber.Packet {
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, "")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", ""))
		return p
	}
	ext := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.FilterExtensibleMatch, nil, "")
	ext.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "x", ""))
	for name, p := range map[string]*ber.Packet{
		"universal-class":       ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ldap.FilterAnd, nil, ""),
		"unknown-tag":           ber.Encode(ber.ClassContext, ber.TypeConstructed, 10, nil, ""),
		"equality-one-child":    short(ldap.FilterEqualityMatch),
		"substrings-one-child":  short(ldap.FilterSubstrings),
		"extensible-bad-child":  ext,
		"present-without-data":  {Identifier: ber.Identifier{ClassType: ber.ClassContext, Tag: ldap.FilterPresent}},
		"equality-nul-in-value": fxLeaf(ldap.FilterEqualityMatch, "cn", "a\x00"),
	} {
		t.Run(name, func(t *testing.T) {
			if checkFilter(p) == "" {
				t.Fatal("malformed packet accepted")
			}
		})
	}
}

func TestCombineRefusesForgedFilters(t *testing.T) {
	ok := fltMust(t, "(uid=a)")
	for name, base := range map[string]Filter{
		"unbalanced":     {canon: "(uid=a"},
		"two-filters":    {canon: "(uid=a)(uid=b)"},
		"not-canonical":  {canon: `(uid=\41)`},
		"not-a-filter-x": {canon: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Combine(base, ok)
			if !errors.Is(err, ErrInvalidFilter) || got != (Filter{}) {
				t.Fatalf("Combine(%q) = %q, %v; want refusal", base.canon, got.canon, err)
			}
		})
	}
}

func TestFilterParseDetail(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"not-ldap":     {errors.New("boom"), "filter is not valid"},
		"nil-inner":    {&ldap.Error{ResultCode: ldap.ErrorFilterCompile}, "filter is not valid"},
		"empty-inner":  {&ldap.Error{Err: errors.New("ldap: ")}, "filter is not valid"},
		"control-char": {&ldap.Error{Err: errors.New("ldap: extra at end: a\x1bb\xff")}, "extra at end: a�b�"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := filterParseDetail(tc.err); got != tc.want {
				t.Fatalf("filterParseDetail = %q, want %q", got, tc.want)
			}
		})
	}

	// A long parser message is cut on a rune boundary.
	in := "(uid=a)" + strings.Repeat("ü", 400)
	_, err := CompileUserFilter(in)
	var fe *FilterError
	if !errors.As(err, &fe) {
		t.Fatalf("CompileUserFilter: %v", err)
	}
	if !utf8.ValidString(fe.Detail) || !strings.HasSuffix(fe.Detail, "…") || len(fe.Detail) > maxFilterDetail+len("…") {
		t.Fatalf("Detail %q is not a bounded rune-safe cut", fe.Detail)
	}
}
