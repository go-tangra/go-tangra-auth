package ldapdir

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Filter validation and combination (research D6, SR-003). Everything here is
// pure: an invalid filter is refused before any network call can exist, and
// nothing the admin typed reaches the server byte-for-byte — only the
// canonical re-serialisation of the compiled filter.

// Filter caps. Length applies to the input and to the canonical form (which
// is what gets stored and sent); depth counts filter elements on the longest
// root-to-leaf path, leaf included; components counts every filter element.
const (
	MaxFilterBytes      = 4096
	maxFilterDepth      = 16
	maxFilterComponents = 64
	// maxFilterDetail bounds a parser message, which may quote the input.
	maxFilterDetail = 256
)

// matchAll is the canonical filter for an empty user or base filter.
const matchAll = "(objectClass=*)"

// Filter is a compiled, policy-checked filter in canonical RFC 4515 form. The
// zero value is not a usable filter; Combine refuses it.
type Filter struct {
	canon string
}

// String returns the canonical filter text ("" for the zero value).
func (f Filter) String() string { return f.canon }

// FilterError is a refused filter. Detail is safe to show the admin who typed
// the filter: the parser's position message or a fixed policy text, as valid
// UTF-8 without control characters. It never carries directory data.
type FilterError struct {
	Detail string
}

func (e *FilterError) Error() string { return ErrInvalidFilter.Error() + ": " + e.Detail }

// Is makes a *FilterError match ErrInvalidFilter.
func (e *FilterError) Is(target error) bool { return target == ErrInvalidFilter }

func refuse(detail string) (Filter, error) { return Filter{}, &FilterError{Detail: detail} }

// CompileUserFilter validates s and returns its canonical form. An empty or
// all-whitespace s matches everything.
func CompileUserFilter(s string) (Filter, error) {
	switch {
	case len(s) > MaxFilterBytes:
		return refuse("filter is longer than 4096 bytes")
	case !utf8.ValidString(s):
		return refuse("filter is not valid UTF-8")
	case strings.IndexByte(s, 0) >= 0:
		return refuse("filter contains a NUL character")
	case strings.TrimSpace(s) == "":
		return Filter{canon: matchAll}, nil
	}
	p, err := ldap.CompileFilter(s)
	if err != nil {
		return refuse(filterParseDetail(err))
	}
	if detail := checkFilter(p); detail != "" {
		return refuse(detail)
	}
	canon, detail := canonicalise(p)
	if detail != "" {
		return refuse(detail)
	}
	return Filter{canon: canon}, nil
}

// canonicalise re-serialises a policy-checked packet. The canonical form must
// itself pass the policy and be a fixed point, so what is stored re-compiles
// to exactly what is sent. It returns a refusal text on failure.
func canonicalise(p *ber.Packet) (canon, detail string) {
	const unstable = "filter cannot be re-serialised"
	canon, err := ldap.DecompileFilter(p)
	if err != nil {
		return "", unstable
	}
	if len(canon) > MaxFilterBytes {
		return "", "filter is longer than 4096 bytes once canonicalised"
	}
	again := ""
	if p2, err := ldap.CompileFilter(canon); err == nil {
		if detail := checkFilter(p2); detail != "" {
			return "", detail
		}
		again, _ = ldap.DecompileFilter(p2)
	}
	if again != canon {
		return "", unstable
	}
	return canon, ""
}

// Combine returns (&base user). Both halves are complete compiled filters, so
// no input can close the AND early; the result is compiled again and its root
// checked to be an AND of exactly base and user.
func Combine(base, user Filter) (Filter, error) {
	if base.canon == "" || user.canon == "" {
		return refuse("filter is missing")
	}
	s := "(&" + base.canon + user.canon + ")"
	p, err := ldap.CompileFilter(s)
	if err != nil || p.ClassType != ber.ClassContext || p.Tag != ldap.FilterAnd || len(p.Children) != 2 {
		return refuse("filters cannot be combined")
	}
	if out, err := ldap.DecompileFilter(p); err != nil || out != s {
		return refuse("filters cannot be combined")
	}
	return Filter{canon: s}, nil
}

// filterParseDetail is go-ldap's own message without the result-code wrapper and
// "ldap: " prefix, bounded and stripped of control characters.
func filterParseDetail(err error) string {
	var le *ldap.Error
	if !errors.As(err, &le) || le.Err == nil {
		return "filter is not valid"
	}
	d := strings.TrimPrefix(le.Err.Error(), "ldap: ")
	d = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(d, string(utf8.RuneError)))
	if len(d) > maxFilterDetail {
		cut := maxFilterDetail
		for cut > 0 && !utf8.RuneStart(d[cut]) {
			cut--
		}
		d = d[:cut] + "…"
	}
	if d == "" {
		return "filter is not valid"
	}
	return d
}

// checkFilter enforces the freya policy on a compiled filter and returns a
// fixed refusal text, or "" when the filter is acceptable.
func checkFilter(p *ber.Packet) string {
	components := 0
	var walk func(p *ber.Packet, depth int) string
	walk = func(p *ber.Packet, depth int) string {
		components++
		switch {
		case depth > maxFilterDepth:
			return "filter nests deeper than 16 levels"
		case components > maxFilterComponents:
			return "filter has more than 64 components"
		case p.ClassType != ber.ClassContext:
			return "filter is not valid"
		}
		switch p.Tag {
		case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
			for _, c := range p.Children {
				if d := walk(c, depth+1); d != "" {
					return d
				}
			}
			return ""
		case ldap.FilterPresent:
			return checkAttr(packetString(p))
		case ldap.FilterEqualityMatch, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual, ldap.FilterApproxMatch:
			if len(p.Children) != 2 {
				return "filter is not valid"
			}
			if d := checkAttr(packetString(p.Children[0])); d != "" {
				return d
			}
			return checkValue(packetString(p.Children[1]))
		case ldap.FilterSubstrings:
			if len(p.Children) != 2 {
				return "filter is not valid"
			}
			if d := checkAttr(packetString(p.Children[0])); d != "" {
				return d
			}
			for _, part := range p.Children[1].Children {
				if d := checkValue(packetString(part)); d != "" {
					return d
				}
			}
			return ""
		case ldap.FilterExtensibleMatch:
			return checkExtensible(p)
		default:
			return "filter is not valid"
		}
	}
	return walk(p, 1)
}

func checkExtensible(p *ber.Packet) string {
	for _, c := range p.Children {
		switch c.Tag {
		case ldap.MatchingRuleAssertionMatchingRule:
			rule := packetString(c)
			if strings.EqualFold(rule, "dn") {
				// go-ldap reads a non-lowercase ":DN:" as a matching rule
				// named DN, which no server knows.
				return "write the :dn: flag in lower case"
			}
			if !isDescriptor(rule) && !isOID(rule) {
				return "filter matching rule is not allowed"
			}
		case ldap.MatchingRuleAssertionType:
			if d := checkAttr(packetString(c)); d != "" {
				return d
			}
		case ldap.MatchingRuleAssertionMatchValue:
			if d := checkValue(packetString(c)); d != "" {
				return d
			}
		case ldap.MatchingRuleAssertionDNAttributes:
			// :dn: also matches the entry's DN components, e.g.
			// (!(ou:dn:=SystemAccounts)) excludes an OU. Results are still
			// re-checked against the base DN, so it cannot widen the search.
		default:
			return "filter is not valid"
		}
	}
	return ""
}

// packetString is a primitive packet's raw octets.
func packetString(p *ber.Packet) string {
	if p.Data == nil {
		return ""
	}
	return p.Data.String()
}

// checkValue refuses assertion values carrying a NUL (for example an escaped
// \00), which directories disagree on.
func checkValue(v string) string {
	if strings.IndexByte(v, 0) >= 0 {
		return "filter contains a NUL character"
	}
	return ""
}

// checkAttr accepts an attribute description: a descriptor or numeric OID,
// followed by options (RFC 4512 §2.5).
func checkAttr(a string) string {
	typ, opts, _ := strings.Cut(a, ";")
	if !isDescriptor(typ) && !isOID(typ) {
		return "filter attribute description is not allowed"
	}
	if strings.Contains(a, ";") {
		for o := range strings.SplitSeq(opts, ";") {
			if o == "" || strings.IndexFunc(o, func(r rune) bool { return !isKeychar(r) }) >= 0 {
				return "filter attribute description is not allowed"
			}
		}
	}
	return ""
}

// isDescriptor reports keystring: ALPHA *(ALPHA / DIGIT / "-").
func isDescriptor(s string) bool {
	if s == "" || !isAlpha(rune(s[0])) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return !isKeychar(r) }) < 0
}

// isOID reports numericoid: number 1*("." number), number without leading
// zeros.
func isOID(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, n := range parts {
		if n == "" || len(n) > 1 && n[0] == '0' {
			return false
		}
		for i := range len(n) {
			if n[i] < '0' || n[i] > '9' {
				return false
			}
		}
	}
	return true
}

func isAlpha(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

func isKeychar(r rune) bool { return isAlpha(r) || r >= '0' && r <= '9' || r == '-' }
