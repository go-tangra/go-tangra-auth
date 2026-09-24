package ldapdir

import (
	"bytes"
	"errors"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func openPlain(t *testing.T, script serverScript) (*ldapTestServer, Session) {
	t.Helper()
	srv := newLDAPServer(t, false, nil, script)
	c, _ := testClient(t, srv.port)
	return srv, mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: TLSModePlain})
}

func TestBindZeroesPassword(t *testing.T) {
	_, s := openPlain(t, serverScript{})
	pw := []byte(passwordSentinel)
	if err := s.Bind(ctxTimeout(t, 5*time.Second), "cn=svc,dc=example,dc=test", pw); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !bytes.Equal(pw, make([]byte, len(pw))) {
		t.Fatal("Bind left the password in the caller's buffer")
	}
}

func TestSearchRefusesInvalidQuery(t *testing.T) {
	srv, s := openPlain(t, serverScript{})
	base := Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 1, TimeLimit: time.Second}
	cases := map[string]func(q *Query){
		"unknown scope":       func(q *Query) { q.Scope = 7 },
		"zero size limit":     func(q *Query) { q.SizeLimit = 0 },
		"negative time limit": func(q *Query) { q.TimeLimit = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := base
			mutate(&q)
			_, err := s.Search(ctxTimeout(t, 5*time.Second), q)
			if !errors.Is(err, ErrDirectory) {
				t.Fatalf("err = %v, want ErrDirectory", err)
			}
			assertSanitised(t, err)
		})
	}

	t.Run("filter that does not compile", func(t *testing.T) {
		q := base
		q.Filter = "(uid=" + passwordSentinel
		_, err := s.Search(ctxTimeout(t, 5*time.Second), q)
		if !errors.Is(err, ErrInvalidFilter) || Reason(err) != "invalid_filter" {
			t.Fatalf("err = %v, want ErrInvalidFilter", err)
		}
		assertSanitised(t, err)
	})

	if n := len(srv.opsWithTag(ldap.ApplicationSearchRequest)); n != 0 {
		t.Fatalf("server saw %d searches for refused queries", n)
	}
}

func TestSearchSubSecondTimeLimitRoundsUp(t *testing.T) {
	var got searchReq
	_, s := openPlain(t, serverScript{search: func(r searchReq) searchReply { got = r; return searchReply{} }})
	if _, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 1, TimeLimit: 200 * time.Millisecond}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got.TimeLimit != 1 {
		t.Fatalf("TimeLimit = %d, want 1 (never 0, which means no limit)", got.TimeLimit)
	}
}

func TestBaseExistsServerIgnoresSizeLimit(t *testing.T) {
	_, s := openPlain(t, serverScript{search: func(searchReq) searchReply { return searchReply{entries: manyEntries(5)} }})
	if err := s.BaseExists(ctxTimeout(t, 5*time.Second), "dc=example,dc=test"); err != nil {
		t.Fatalf("BaseExists: %v", err)
	}
}

// A hostile entry whose DN is not an OCTET STRING makes go-ldap panic while
// decoding it; the panic stays inside the session.
func TestSearchContainsDecoderPanic(t *testing.T) {
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
	entry.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(42), "dn"))
	entry.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes"))
	raw := envelope(1, entry).Bytes() // first request on a plain session has message ID 1

	_, s := openPlain(t, serverScript{search: func(searchReq) searchReply { return searchReply{raw: raw} }})
	start := time.Now()
	page, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 5, TimeLimit: time.Second})
	wantClosed(t, err, ErrDirectory, start)
	if len(page.Entries) != 0 {
		t.Fatalf("entries returned from a hostile packet: %+v", page)
	}
}
