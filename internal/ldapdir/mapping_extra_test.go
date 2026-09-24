package ldapdir

import (
	"errors"
	"testing"
)

func TestDecodeNameNotUTF8IsDropped(t *testing.T) {
	m := Mapping{UID: "uid", Email: "mail", DisplayName: "displayName", FirstName: "givenName"}
	e := RawEntry{DN: testDN, Attrs: map[string][][]byte{
		"uid":         {[]byte("jdoe")},
		"mail":        {[]byte("jdoe@example.test")},
		"displayname": {{0xff, 0xfe}},
		"givenname":   {[]byte("John")},
	}}
	p, err := Decode(m, e)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.DisplayName != "John" || p.DisplayNameExplicit {
		t.Fatalf("display = %q explicit=%v, want fallback", p.DisplayName, p.DisplayNameExplicit)
	}
}

func TestDecodeRefusesControlAndNonUTF8(t *testing.T) {
	cases := []struct {
		name string
		uid  []byte
		mail []byte
		want error
	}{
		{"uid NUL", []byte("jd\x00oe"), []byte("a@example.test"), ErrInvalidUID},
		{"uid blank", []byte("   "), []byte("a@example.test"), ErrInvalidUID},
		{"mail NUL", []byte("jdoe"), []byte("a\x00b@example.test"), ErrInvalidEmail},
		{"mail not utf8", []byte("jdoe"), []byte{'a', 0xff, '@', 'b'}, ErrInvalidEmail},
	}
	for _, c := range cases {
		e := RawEntry{DN: testDN, Attrs: map[string][][]byte{"uid": {c.uid}, "mail": {c.mail}}}
		if _, err := Decode(Mapping{UID: "uid", Email: "mail"}, e); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}
