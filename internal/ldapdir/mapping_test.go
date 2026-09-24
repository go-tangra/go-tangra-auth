package ldapdir

import (
	"errors"
	"strings"
	"testing"
)

// Attribute mapping and entry decoding (research D7/D8, data-model
// "Validation rules"). Every value that comes back from a directory is
// hostile: it is decoded, bounded and normalised here before it can become a
// user row, and an entry that does not fit is marked invalid with a reason,
// never silently truncated into a different identity.

// rawEntry builds a RawEntry the way Session.Search returns it: attribute names
// lower-cased, values as raw bytes.
func rawEntry(dn string, attrs map[string][]string) RawEntry {
	e := RawEntry{DN: dn, Attrs: map[string][][]byte{}}
	for k, vs := range attrs {
		for _, v := range vs {
			e.Attrs[strings.ToLower(k)] = append(e.Attrs[strings.ToLower(k)], []byte(v))
		}
	}
	return e
}

const testDN = "uid=jdoe,ou=people,dc=example,dc=test"

// adGUIDBytes is objectGUID 00112233-4455-6677-8899-aabbccddeeff as AD sends
// it: the first three groups little-endian, the last two in byte order.
var adGUIDBytes = []byte{
	0x33, 0x22, 0x11, 0x00,
	0x55, 0x44,
	0x77, 0x66,
	0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

func openLDAPMapping() Mapping { return DefaultMapping("openldap") }

func TestDefaultMappingPerKind(t *testing.T) {
	// Same presets the directory service offers (T024/T035): AD and OpenLDAP
	// get a full mapping, "other" only the mail default and must name its
	// unique-id attribute.
	cases := map[string]Mapping{
		"active_directory": {UID: "objectGUID", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"},
		"openldap":         {UID: "entryUUID", Email: "mail", DisplayName: "cn", FirstName: "givenName", LastName: "sn"},
		"other":            {Email: "mail"},
	}
	for kind, want := range cases {
		if got := DefaultMapping(kind); got != want {
			t.Errorf("DefaultMapping(%q) = %+v, want %+v", kind, got, want)
		}
	}
}

func TestDecodeADObjectGUID(t *testing.T) {
	m := DefaultMapping("active_directory")
	e := RawEntry{DN: "CN=John Doe,OU=People,DC=example,DC=test", Attrs: map[string][][]byte{
		"objectguid":  {adGUIDBytes},
		"mail":        {[]byte("jdoe@example.test")},
		"displayname": {[]byte("John Doe")},
		"givenname":   {[]byte("John")},
		"sn":          {[]byte("Doe")},
	}}
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := Person{
		UID:                 "00112233-4455-6677-8899-aabbccddeeff",
		DN:                  e.DN,
		Email:               "jdoe@example.test",
		DisplayName:         "John Doe",
		FirstName:           "John",
		LastName:            "Doe",
		DisplayNameExplicit: true,
	}
	if p != want {
		t.Fatalf("Decode = %+v, want %+v", p, want)
	}
}

func TestDecodeGUIDIsCanonicalLowerCase(t *testing.T) {
	// A real-looking GUID with high bytes: canonical form is lower-case hex
	// with dashes, little-endian first three groups.
	raw := []byte{
		0xe0, 0x04, 0x25, 0x3f, // 3f2504e0
		0x89, 0x4f, // 4f89
		0xd3, 0x11, // 11d3
		0x9a, 0x0c, // 9a0c
		0x03, 0x05, 0xe8, 0x2c, 0x33, 0x01, // 0305e82c3301
	}
	e := RawEntry{DN: testDN, Attrs: map[string][][]byte{
		"objectguid": {raw},
		"mail":       {[]byte("a@example.test")},
	}}
	p, err := Decode(DefaultMapping("active_directory"), e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.UID != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("UID = %q", p.UID)
	}
}

func TestDecodeGUIDAttributeNameIsCaseInsensitive(t *testing.T) {
	// The mapping is operator-typed; RawEntry keys are lower-cased.
	for _, attr := range []string{"objectGUID", "objectguid", "OBJECTGUID"} {
		m := Mapping{UID: attr, Email: "mail"}
		e := RawEntry{DN: testDN, Attrs: map[string][][]byte{
			"objectguid": {adGUIDBytes},
			"mail":       {[]byte("a@example.test")},
		}}
		p, err := Decode(m, e)
		if err != nil {
			t.Fatalf("%s: Decode: %v", attr, err)
		}
		if p.UID != "00112233-4455-6677-8899-aabbccddeeff" {
			t.Fatalf("%s: UID = %q", attr, p.UID)
		}
	}
}

func TestDecodeGUIDWrongLengthIsInvalid(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 32, 36} {
		raw := make([]byte, n)
		e := RawEntry{DN: testDN, Attrs: map[string][][]byte{
			"objectguid": {raw},
			"mail":       {[]byte("a@example.test")},
		}}
		p, err := Decode(DefaultMapping("active_directory"), e)
		if !errors.Is(err, ErrInvalidUID) {
			t.Fatalf("len %d: err = %v, want ErrInvalidUID", n, err)
		}
		if p.UID != "" {
			t.Fatalf("len %d: UID = %q, want empty on invalid uid", n, p.UID)
		}
	}
	// The string form of a GUID is 36 bytes, not 16: an AD server (or a
	// hostile one) sending text is not accepted as a GUID either.
	e := RawEntry{DN: testDN, Attrs: map[string][][]byte{
		"objectguid": {[]byte("00112233-4455-6677-8899-aabbccddeeff")},
		"mail":       {[]byte("a@example.test")},
	}}
	if _, err := Decode(DefaultMapping("active_directory"), e); !errors.Is(err, ErrInvalidUID) {
		t.Fatalf("textual GUID: err = %v, want ErrInvalidUID", err)
	}
}

func TestDecodeEntryUUIDString(t *testing.T) {
	e := rawEntry(testDN, map[string][]string{
		"entryUUID": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
		"mail":      {"jdoe@example.test"},
		"cn":        {"John Doe"},
	})
	p, err := Decode(openLDAPMapping(), e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.UID != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("UID = %q", p.UID)
	}
	if p.DN != testDN {
		t.Fatalf("DN = %q", p.DN)
	}
}

func TestDecodeOtherKindStringUIDVerbatim(t *testing.T) {
	// Any attribute can be the unique id for "other"; its value is used
	// verbatim so the import re-fetch (uid_attr=<escaped uid>) matches it.
	m := Mapping{UID: "uid", Email: "mail"}
	e := rawEntry(testDN, map[string][]string{"uid": {"JDoe"}, "mail": {"jdoe@example.test"}})
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.UID != "JDoe" {
		t.Fatalf("UID = %q, want verbatim JDoe", p.UID)
	}
}

func TestDecodeMultiValuedUID(t *testing.T) {
	cases := map[string]RawEntry{
		"string": rawEntry(testDN, map[string][]string{"uid": {"jdoe", "john"}, "mail": {"jdoe@example.test"}}),
		"guid": {DN: testDN, Attrs: map[string][][]byte{
			"objectguid": {adGUIDBytes, adGUIDBytes},
			"mail":       {[]byte("jdoe@example.test")},
		}},
	}
	maps := map[string]Mapping{
		"string": {UID: "uid", Email: "mail"},
		"guid":   DefaultMapping("active_directory"),
	}
	for name, e := range cases {
		p, err := Decode(maps[name], e)
		if !errors.Is(err, ErrMultiValuedUID) {
			t.Fatalf("%s: err = %v, want ErrMultiValuedUID", name, err)
		}
		if p.UID != "" {
			t.Fatalf("%s: UID = %q, want empty (no value is picked)", name, p.UID)
		}
		if p.DN != testDN {
			t.Fatalf("%s: DN = %q, want it kept for the preview row", name, p.DN)
		}
	}
}

func TestDecodeMissingOrEmptyUID(t *testing.T) {
	cases := map[string]RawEntry{
		"absent":   rawEntry(testDN, map[string][]string{"mail": {"jdoe@example.test"}}),
		"empty":    rawEntry(testDN, map[string][]string{"uid": {""}, "mail": {"jdoe@example.test"}}),
		"nil map":  {DN: testDN},
		"not utf8": {DN: testDN, Attrs: map[string][][]byte{"uid": {{0xff, 0xfe, 'a'}}, "mail": {[]byte("a@example.test")}}},
	}
	for name, e := range cases {
		if _, err := Decode(Mapping{UID: "uid", Email: "mail"}, e); !errors.Is(err, ErrInvalidUID) {
			t.Errorf("%s: err = %v, want ErrInvalidUID", name, err)
		}
	}
	// No uid attribute configured at all ("other" without a uid).
	e := rawEntry(testDN, map[string][]string{"uid": {"jdoe"}, "mail": {"jdoe@example.test"}})
	if _, err := Decode(DefaultMapping("other"), e); !errors.Is(err, ErrInvalidUID) {
		t.Errorf("unmapped uid: err = %v, want ErrInvalidUID", err)
	}
}

func TestDecodeValueCaps(t *testing.T) {
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}
	base := func() map[string][]string {
		return map[string][]string{
			"uid":         {"jdoe"},
			"mail":        {"jdoe@example.test"},
			"displayname": {"John Doe"},
			"givenname":   {"John"},
			"sn":          {"Doe"},
		}
	}
	// Exactly at each cap is accepted.
	atCap := base()
	atCap["uid"] = []string{strings.Repeat("u", 256)}
	atCap["mail"] = []string{strings.Repeat("a", 254-len("@example.test")) + "@example.test"}
	atCap["displayname"] = []string{strings.Repeat("d", 100)}
	atCap["givenname"] = []string{strings.Repeat("f", 100)}
	atCap["sn"] = []string{strings.Repeat("l", 100)}
	dnAtCap := "uid=x," + strings.Repeat("o", 1024-len("uid=x,"))
	if _, err := Decode(m, rawEntry(dnAtCap, atCap)); err != nil {
		t.Fatalf("values at cap: %v", err)
	}

	over := map[string]func(a map[string][]string) string{
		"uid 257 bytes": func(a map[string][]string) string {
			a["uid"] = []string{strings.Repeat("u", 257)}
			return testDN
		},
		"email 255 bytes": func(a map[string][]string) string {
			a["mail"] = []string{strings.Repeat("a", 255-len("@example.test")) + "@example.test"}
			return testDN
		},
		"display name 101": func(a map[string][]string) string {
			a["displayname"] = []string{strings.Repeat("d", 101)}
			return testDN
		},
		"first name 101": func(a map[string][]string) string {
			a["givenname"] = []string{strings.Repeat("f", 101)}
			return testDN
		},
		"last name 101": func(a map[string][]string) string {
			a["sn"] = []string{strings.Repeat("l", 101)}
			return testDN
		},
		"dn 1025": func(map[string][]string) string {
			return "uid=x," + strings.Repeat("o", 1025-len("uid=x,"))
		},
		// user.ValidateName counts bytes: 51 two-byte runes are 102 bytes.
		"multibyte name": func(a map[string][]string) string {
			a["givenname"] = []string{strings.Repeat("é", 51)}
			return testDN
		},
	}
	for name, mutate := range over {
		a := base()
		dn := mutate(a)
		_, err := Decode(m, rawEntry(dn, a))
		if !errors.Is(err, ErrValueTooLong) {
			t.Errorf("%s: err = %v, want ErrValueTooLong", name, err)
		}
	}
}

func TestDecodeSixteenByteStringUIDIsNotAGUID(t *testing.T) {
	// Only the objectGUID attribute is decoded as a binary GUID; a 16-byte
	// value of any other uid attribute is used verbatim.
	m := Mapping{UID: "uid", Email: "mail"}
	e := rawEntry(testDN, map[string][]string{"uid": {"0123456789abcdef"}, "mail": {"a@example.test"}})
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.UID != "0123456789abcdef" {
		t.Fatalf("UID = %q, want the 16-byte string verbatim", p.UID)
	}
}

func TestDecodeMissingEmail(t *testing.T) {
	cases := map[string]struct {
		m Mapping
		e RawEntry
	}{
		"absent":       {openLDAPMapping(), rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "cn": {"John"}})},
		"empty value":  {openLDAPMapping(), rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {""}, "cn": {"John"}})},
		"blank value":  {openLDAPMapping(), rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {"   "}, "cn": {"John"}})},
		"not mapped":   {Mapping{UID: "entryUUID", DisplayName: "cn"}, rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {"a@example.test"}, "cn": {"John"}})},
		"empty values": {openLDAPMapping(), RawEntry{DN: testDN, Attrs: map[string][][]byte{"entryuuid": {[]byte("u1")}, "mail": {}, "cn": {[]byte("John")}}}},
	}
	for name, c := range cases {
		p, err := Decode(c.m, c.e)
		if !errors.Is(err, ErrNoEmail) {
			t.Errorf("%s: err = %v, want ErrNoEmail", name, err)
			continue
		}
		// The preview still shows the row (status invalid, reason no_email).
		if p.UID != "u1" || p.DN != testDN || p.DisplayName != "John" || p.Email != "" {
			t.Errorf("%s: Person = %+v, want uid/dn/display kept and no email", name, p)
		}
	}
}

func TestDecodeInvalidEmail(t *testing.T) {
	for _, raw := range []string{
		"no-at-sign",
		"@example.test",
		"jdoe@",
		"jdoe @example.test",
		"jdoe@exa\tmple.test",
		"jd\noe@example.test",
	} {
		e := rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {raw}, "cn": {"John"}})
		p, err := Decode(openLDAPMapping(), e)
		if !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%q: err = %v, want ErrInvalidEmail", raw, err)
			continue
		}
		if p.Email != "" || p.UID != "u1" {
			t.Errorf("%q: Person = %+v, want uid kept and no email", raw, p)
		}
	}
}

// inviteNormEmail mirrors invite.normEmail (services/auth/internal/invite),
// the rule invitations use. Decode must accept exactly the addresses it
// accepts, produce the same normalised form, and reject everything it
// rejects (as invalid_email, or value_too_long past 254 bytes), so an
// imported e-mail and a later invitation to it always collide.
func inviteNormEmail(e string) (string, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	at := strings.IndexByte(e, '@')
	if at <= 0 || at == len(e)-1 || strings.ContainsAny(e, " \t\r\n") || len(e) > 254 {
		return "", false
	}
	return e, true
}

func TestDecodeEmailNormalisationMatchesInvitations(t *testing.T) {
	inputs := []string{
		"jdoe@example.test",
		"JDoe@Example.TEST",
		"  jdoe@example.test  ",
		"\tJDOE@EXAMPLE.TEST\n",
		"first.last+tag@sub.example.test",
		"a@b",
		"a@b@c",
		"ÄRGER@example.test",
		"no-at",
		"@x",
		"x@",
		"x @y",
		"x@y\rz",
		strings.Repeat("a", 250) + "@b.c",
		strings.Repeat("a", 251) + "@b.c",
	}
	for _, raw := range inputs {
		e := rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {raw}})
		p, err := Decode(openLDAPMapping(), e)
		want, ok := inviteNormEmail(raw)
		if ok {
			if err != nil {
				t.Errorf("%q: invitations accept it, Decode: %v", raw, err)
				continue
			}
			if p.Email != want {
				t.Errorf("%q: Email = %q, invitations normalise to %q", raw, p.Email, want)
			}
			continue
		}
		if !errors.Is(err, ErrInvalidEmail) && !errors.Is(err, ErrValueTooLong) {
			t.Errorf("%q: invitations reject it, Decode err = %v", raw, err)
		}
	}
}

func TestDecodeMultiValuedMailUsesFirstValue(t *testing.T) {
	// mail is multi-valued in inetOrgPerson; the first value is the address.
	e := rawEntry(testDN, map[string][]string{"entryuuid": {"u1"}, "mail": {"First@example.test", "second@example.test"}})
	p, err := Decode(openLDAPMapping(), e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Email != "first@example.test" {
		t.Fatalf("Email = %q", p.Email)
	}
}

func TestDecodeNamesThroughValidateName(t *testing.T) {
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}
	e := rawEntry(testDN, map[string][]string{
		"uid":         {"jdoe"},
		"mail":        {"jdoe@example.test"},
		"displayname": {"  John Q. Doe  "},
		"givenname":   {"\tJohn "},
		"sn":          {" Doe\n"},
	})
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.DisplayName != "John Q. Doe" || p.FirstName != "John" || p.LastName != "Doe" {
		t.Fatalf("names = %q/%q/%q, want trimmed by user.ValidateName", p.DisplayName, p.FirstName, p.LastName)
	}
}

func TestDecodeNameWithControlCharacterIsDropped(t *testing.T) {
	// user.ValidateName refuses control characters. A name is not identity,
	// so the value is dropped (and the display-name fallback applies) rather
	// than the whole entry being refused.
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}
	e := rawEntry(testDN, map[string][]string{
		"uid":         {"jdoe"},
		"mail":        {"jdoe@example.test"},
		"displayname": {"John\x00Doe"},
		"givenname":   {"Jo\x1bhn"},
		"sn":          {"Doe"},
	})
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.FirstName != "" || p.LastName != "Doe" {
		t.Fatalf("first/last = %q/%q, want control-char name dropped", p.FirstName, p.LastName)
	}
	if p.DisplayName != "Doe" || p.DisplayNameExplicit {
		t.Fatalf("display = %q explicit=%v, want fallback from names", p.DisplayName, p.DisplayNameExplicit)
	}
}

func TestDecodeDisplayNameFallback(t *testing.T) {
	full := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}
	cases := []struct {
		name         string
		m            Mapping
		attrs        map[string][]string
		wantDisplay  string
		wantExplicit bool
	}{
		{"explicit", full, map[string][]string{"displayname": {"Johnny"}, "givenname": {"John"}, "sn": {"Doe"}}, "Johnny", true},
		{"first and last", full, map[string][]string{"givenname": {"John"}, "sn": {"Doe"}}, "John Doe", false},
		{"blank display", full, map[string][]string{"displayname": {"   "}, "givenname": {"John"}, "sn": {"Doe"}}, "John Doe", false},
		{"first only", full, map[string][]string{"givenname": {"John"}}, "John", false},
		{"last only", full, map[string][]string{"sn": {"Doe"}}, "Doe", false},
		{"email local part", full, map[string][]string{}, "jdoe", false},
		{"display not mapped", Mapping{UID: "uid", Email: "mail", FirstName: "givenName"}, map[string][]string{"displayname": {"Ignored"}, "givenname": {"John"}}, "John", false},
	}
	for _, c := range cases {
		c.attrs["uid"] = []string{"jdoe"}
		c.attrs["mail"] = []string{"JDoe@Example.test"}
		p, err := Decode(c.m, rawEntry(testDN, c.attrs))
		if err != nil {
			t.Errorf("%s: Decode: %v", c.name, err)
			continue
		}
		if p.DisplayName != c.wantDisplay || p.DisplayNameExplicit != c.wantExplicit {
			t.Errorf("%s: display = %q explicit=%v, want %q explicit=%v",
				c.name, p.DisplayName, p.DisplayNameExplicit, c.wantDisplay, c.wantExplicit)
		}
	}
}

func TestDecodeFirstNameAndLastNameOptional(t *testing.T) {
	// Unmapped first/last attributes leave the names empty, even if the entry
	// happens to carry givenName/sn.
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "cn"}
	e := rawEntry(testDN, map[string][]string{"uid": {"jdoe"}, "mail": {"jdoe@example.test"}, "cn": {"John Doe"}, "givenname": {"John"}, "sn": {"Doe"}})
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.FirstName != "" || p.LastName != "" || p.DisplayName != "John Doe" {
		t.Fatalf("Person = %+v", p)
	}
}

func TestDecodeReasonPrecedence(t *testing.T) {
	// uid problems first (the row cannot be imported by uid at all), then
	// over-long values, then e-mail problems.
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName"}
	cases := []struct {
		name  string
		attrs map[string][]string
		want  error
	}{
		{"multi uid beats no email", map[string][]string{"uid": {"a", "b"}}, ErrMultiValuedUID},
		{"invalid uid beats too long", map[string][]string{"displayname": {strings.Repeat("d", 101)}}, ErrInvalidUID},
		{"too long beats no email", map[string][]string{"uid": {"a"}, "displayname": {strings.Repeat("d", 101)}}, ErrValueTooLong},
		{"too long beats invalid email", map[string][]string{"uid": {"a"}, "mail": {"bad"}, "displayname": {strings.Repeat("d", 101)}}, ErrValueTooLong},
	}
	for _, c := range cases {
		if _, err := Decode(m, rawEntry(testDN, c.attrs)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestDecodeErrorsAreClosedAndCarryNoValues(t *testing.T) {
	// Reasons are the SearchResult/ImportResult vocabulary; error strings
	// never echo directory values (they end up in logs).
	secret := "leak-me-" + strings.Repeat("x", 300)
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName"}
	cases := []struct {
		attrs  map[string][]string
		want   error
		reason string
	}{
		{map[string][]string{"uid": {"u1"}}, ErrNoEmail, "no_email"},
		{map[string][]string{"uid": {"u1"}, "mail": {"leak-me-no-at"}}, ErrInvalidEmail, "invalid_email"},
		{map[string][]string{"uid": {"u1"}, "mail": {"a@b"}, "displayname": {secret}}, ErrValueTooLong, "value_too_long"},
		{map[string][]string{"uid": {"leak-me-1", "leak-me-2"}, "mail": {"a@b"}}, ErrMultiValuedUID, "multi_valued_uid"},
		{map[string][]string{"mail": {"a@b"}}, ErrInvalidUID, "invalid_uid"},
	}
	for _, c := range cases {
		_, err := Decode(m, rawEntry(testDN, c.attrs))
		if !errors.Is(err, c.want) {
			t.Errorf("err = %v, want %v", err, c.want)
			continue
		}
		if got := Reason(err); got != c.reason {
			t.Errorf("Reason(%v) = %q, want %q", err, got, c.reason)
		}
		if strings.Contains(err.Error(), "leak-me") || strings.Contains(err.Error(), "example.test") {
			t.Errorf("error text %q echoes a directory value", err.Error())
		}
	}
}
