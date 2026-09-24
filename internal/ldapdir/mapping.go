package ldapdir

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-freya/freya/services/auth/internal/user"
)

// Attribute mapping and entry decoding (research D7/D8). Every value a
// directory returns is hostile: it is decoded, bounded and normalised here
// before it can become a user row. An entry that does not fit is reported
// with a closed reason, never truncated into a different identity.

// Per-value caps after decoding (research D7). Names use user.NameMax.
const (
	MaxUIDBytes   = 256
	MaxEmailBytes = 254
	MaxDNBytes    = 1024
)

// Decode refusals. Their text never carries a directory value.
var (
	// ErrNoEmail reports an entry without a usable e-mail value.
	ErrNoEmail = errors.New("ldapdir: entry has no email")
	// ErrInvalidEmail reports an e-mail value invitations would refuse.
	ErrInvalidEmail = errors.New("ldapdir: entry email invalid")
	// ErrValueTooLong reports a value over its per-value cap.
	ErrValueTooLong = errors.New("ldapdir: entry value too long")
	// ErrMultiValuedUID reports a unique-id attribute with several values.
	ErrMultiValuedUID = errors.New("ldapdir: entry unique id is multi-valued")
	// ErrInvalidUID reports a missing, empty or undecodable unique id.
	ErrInvalidUID = errors.New("ldapdir: entry unique id invalid")
)

// objectGUIDAttr is the only attribute decoded as a binary GUID.
const objectGUIDAttr = "objectguid"

// Mapping names the directory attribute behind each person field. Empty
// means not mapped.
type Mapping struct {
	UID, Email, DisplayName, FirstName, LastName string
}

// Person is a decoded directory entry. DisplayNameExplicit is false when
// DisplayName was derived from the names or the e-mail.
type Person struct {
	UID, DN, Email, DisplayName, FirstName, LastName string
	DisplayNameExplicit                              bool
}

// DefaultMapping returns the preset for a connection kind. "other" (and any
// unknown kind) maps only mail; the operator must name the unique id.
func DefaultMapping(kind string) Mapping {
	switch kind {
	case "active_directory":
		return Mapping{UID: "objectGUID", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}
	case "openldap":
		return Mapping{UID: "entryUUID", Email: "mail", DisplayName: "cn", FirstName: "givenName", LastName: "sn"}
	default:
		return Mapping{Email: "mail"}
	}
}

// Decode turns e into a Person under m. On error the Person still carries
// every field that decoded (for the preview row); the failing field is empty.
// Error precedence: unique id, then over-long values, then e-mail.
func Decode(m Mapping, e RawEntry) (Person, error) { //nolint:gocritic // hugeParam: signature pinned by the tests-first suite
	var p Person
	uidErr := decodeUID(m.UID, e, &p)

	var tooLong error
	if len(e.DN) > MaxDNBytes {
		tooLong = ErrValueTooLong
	} else {
		p.DN = e.DN
	}

	var err error
	if p.FirstName, err = decodeName(m.FirstName, e); err != nil {
		tooLong = err
	}
	if p.LastName, err = decodeName(m.LastName, e); err != nil {
		tooLong = err
	}
	display, err := decodeName(m.DisplayName, e)
	if err != nil {
		tooLong = err
	}

	emailErr := decodeEmail(m.Email, e, &p)
	if errors.Is(emailErr, ErrValueTooLong) {
		tooLong, emailErr = emailErr, nil
	}

	if display != "" {
		p.DisplayName, p.DisplayNameExplicit = display, true
	} else {
		p.DisplayName = user.DeriveDisplayName(p.FirstName, p.LastName, "", p.Email)
	}

	switch {
	case uidErr != nil:
		return p, uidErr
	case tooLong != nil:
		return p, tooLong
	default:
		return p, emailErr
	}
}

// values returns the values of the mapped attribute (nil when unmapped).
func values(attr string, e RawEntry) [][]byte {
	if attr == "" {
		return nil
	}
	return e.Attrs[strings.ToLower(attr)]
}

// decodeUID sets p.UID. objectGUID is 16 raw bytes rendered as the canonical
// GUID string; any other attribute is used verbatim so the import re-fetch
// (uid_attr=<escaped uid>) matches it.
func decodeUID(attr string, e RawEntry, p *Person) error {
	vs := values(attr, e)
	switch {
	case len(vs) == 0:
		return ErrInvalidUID
	case len(vs) > 1:
		return ErrMultiValuedUID
	}
	v := vs[0]
	if strings.EqualFold(attr, objectGUIDAttr) {
		if len(v) != 16 {
			return ErrInvalidUID
		}
		p.UID = formatGUID(v)
		return nil
	}
	s := string(v)
	if strings.TrimSpace(s) == "" || !utf8.ValidString(s) || hasControl(s) {
		return ErrInvalidUID
	}
	if len(s) > MaxUIDBytes {
		return ErrValueTooLong
	}
	p.UID = s
	return nil
}

// formatGUID renders AD objectGUID bytes: the first three groups are
// little-endian, the last two in byte order.
func formatGUID(b []byte) string {
	g := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]}
	g = append(g, b[8:16]...)
	h := hex.EncodeToString(g)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// decodeEmail sets p.Email to the first value, normalised with the rules
// invitations use (invite.normEmail), so an imported address and a later
// invitation to it always collide. Invalid UTF-8 and control characters are
// refused as well.
func decodeEmail(attr string, e RawEntry, p *Person) error {
	vs := values(attr, e)
	if len(vs) == 0 {
		return ErrNoEmail
	}
	raw := string(vs[0])
	if strings.TrimSpace(raw) == "" {
		return ErrNoEmail
	}
	// Check UTF-8 first: strings.ToLower would replace invalid bytes.
	if !utf8.ValidString(raw) {
		return ErrInvalidEmail
	}
	s := strings.ToLower(strings.TrimSpace(raw))
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || strings.ContainsAny(s, " \t\r\n") || hasControl(s) {
		return ErrInvalidEmail
	}
	if len(s) > MaxEmailBytes {
		return ErrValueTooLong
	}
	p.Email = s
	return nil
}

// decodeName returns the first value through user.ValidateName. An over-long
// value is ErrValueTooLong; a value that is not valid UTF-8 or carries a
// control character is dropped, since a name is not identity.
func decodeName(attr string, e RawEntry) (string, error) {
	vs := values(attr, e)
	if len(vs) == 0 {
		return "", nil
	}
	s := string(vs[0])
	if len(strings.TrimSpace(s)) > user.NameMax {
		return "", ErrValueTooLong
	}
	if !utf8.ValidString(s) {
		return "", nil
	}
	n, err := user.ValidateName(s)
	if err != nil {
		return "", nil //nolint:nilerr // a control character drops the name, not the entry
	}
	return n, nil
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
