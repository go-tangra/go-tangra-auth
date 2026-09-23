package ldapfake

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/ldapdir"
)

const (
	baseDN = "dc=example,dc=test"
	bindDN = "cn=reader,dc=example,dc=test"
	bindPW = "fake-bind-password"
)

var ldaps = ldapdir.ConnParams{URL: "ldaps://ldap.example.test", TLSMode: ldapdir.TLSModeLDAPS}

func person(uid, mail string) Entry {
	return Entry{
		DN: "uid=" + uid + ",ou=people," + baseDN,
		Attrs: map[string][][]byte{
			"objectClass": Vals("top", "inetOrgPerson"),
			"uid":         Vals(uid),
			"mail":        Vals(mail),
			"cn":          Vals("Person " + uid),
		},
	}
}

func fixture(t *testing.T) *Directory {
	t.Helper()
	d := New()
	d.Add(Entry{DN: baseDN, Attrs: map[string][][]byte{"objectClass": Vals("domain")}})
	d.Add(Entry{DN: "ou=people," + baseDN, Attrs: map[string][][]byte{"objectClass": Vals("organizationalUnit")}})
	d.Add(person("alice", "Alice@Example.test"))
	d.Add(person("bob", "bob@example.test"))
	d.Add(Entry{DN: "uid=carol,ou=deep,ou=people," + baseDN, Attrs: map[string][][]byte{
		"objectClass": Vals("inetOrgPerson"), "uid": Vals("carol"),
	}})
	d.Add(Entry{DN: "uid=mallory,dc=other,dc=test", Attrs: map[string][][]byte{
		"objectClass": Vals("inetOrgPerson"), "uid": Vals("mallory"), "mail": Vals("m@other.test"),
	}})
	d.SetCredentials(bindDN, bindPW)
	return d
}

func open(t *testing.T, d *Directory) ldapdir.Session {
	t.Helper()
	s, err := d.Open(context.Background(), ldaps)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func query(filter string) ldapdir.Query {
	return ldapdir.Query{
		BaseDN: baseDN, Filter: filter, Attributes: []string{"uid", "mail"},
		SizeLimit: 10, TimeLimit: 1500 * time.Millisecond,
	}
}

//nolint:gocritic // hugeParam: mirrors Session.Search.
func search(t *testing.T, s ldapdir.Session, q ldapdir.Query) ldapdir.Page {
	t.Helper()
	p, err := s.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search(%q): %v", q.Filter, err)
	}
	return p
}

func dns(p ldapdir.Page) []string {
	out := make([]string, len(p.Entries))
	for i, e := range p.Entries {
		out[i] = e.DN
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestImplementsDirectory(t *testing.T) {
	var _ ldapdir.Directory = New()
}

func TestOpenRecordsAndTLSState(t *testing.T) {
	d := New()
	d.SetTLSVersion(tls.VersionTLS12)
	s := open(t, d)
	st, ok := s.TLSState()
	if !ok || st.Version != tls.VersionTLS12 || !st.HandshakeComplete {
		t.Fatalf("TLSState = %+v, %v", st, ok)
	}
	plain, err := d.Open(context.Background(), ldapdir.ConnParams{URL: "ldap://x", TLSMode: ldapdir.TLSModePlain})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.TLSState(); ok {
		t.Fatal("plain session reports TLS")
	}
	if got := d.Opens(); len(got) != 2 || got[0] != ldaps {
		t.Fatalf("Opens = %+v", got)
	}
	if d.OpenSessions() != 2 {
		t.Fatalf("OpenSessions = %d", d.OpenSessions())
	}
	for range 2 {
		if err := plain.Close(); err != nil {
			t.Fatalf("Close = %v, want idempotent nil", err)
		}
	}
	if d.OpenSessions() != 1 {
		t.Fatalf("OpenSessions after close = %d", d.OpenSessions())
	}
	if err := plain.BaseExists(context.Background(), baseDN); !errors.Is(err, ldapdir.ErrUnreachable) {
		t.Fatalf("use after close = %v", err)
	}
}

func TestOpenCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Open(ctx, ldaps); !errors.Is(err, ldapdir.ErrTimeout) {
		t.Fatalf("Open = %v", err)
	}
}

func TestBind(t *testing.T) {
	d := fixture(t)
	s := open(t, d)
	cases := []struct {
		name, dn, pw string
		want         error
	}{
		{"ok", bindDN, bindPW, nil},
		{"dn case-insensitive", "CN=Reader,DC=Example,DC=Test", bindPW, nil},
		{"wrong password", bindDN, "nope", ldapdir.ErrInvalidCredentials},
		{"unknown dn", "cn=ghost," + baseDN, bindPW, ldapdir.ErrInvalidCredentials},
		{"bad dn", "not a dn", bindPW, ldapdir.ErrInvalidCredentials},
		{"empty password", bindDN, "", ldapdir.ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pw := []byte(tc.pw)
			if err := s.Bind(context.Background(), tc.dn, pw); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("Bind = %v, want %v", err, tc.want)
			}
			for _, b := range pw {
				if b != 0 {
					t.Fatal("password slice not zeroed")
				}
			}
		})
	}
	binds := d.Binds()
	if len(binds) != len(cases) || binds[0] != (BindCall{DN: bindDN, Password: bindPW}) {
		t.Fatalf("Binds = %+v", binds)
	}
}

func TestBaseExists(t *testing.T) {
	d := fixture(t)
	d.AddAlias("cn=alias,"+baseDN, "uid=mallory,dc=other,dc=test")
	d.AddReferral("ou=remote,"+baseDN, "ldap://remote.example.test/ou=remote")
	s := open(t, d)
	ctx := context.Background()
	for dn, want := range map[string]error{
		baseDN:                        nil,
		"OU=People," + baseDN:         nil,
		"cn=alias," + baseDN:          nil, // the alias object itself, not dereferenced
		"ou=missing," + baseDN:        ldapdir.ErrBaseNotFound,
		"garbage":                     ldapdir.ErrBaseNotFound,
		"ou=x,ou=remote," + baseDN:    ldapdir.ErrDirectory,
		"ou=deep,ou=people," + baseDN: ldapdir.ErrBaseNotFound, // parents are not implicit
	} {
		if err := s.BaseExists(ctx, dn); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("BaseExists(%q) = %v, want %v", dn, err, want)
		}
	}
	var de *ldapdir.DirectoryError
	if err := s.BaseExists(ctx, "ou=remote,"+baseDN); !errors.As(err, &de) || de.Code != 10 {
		t.Fatalf("referral base = %v", err)
	}
	if got := d.BaseChecks(); len(got) != 8 {
		t.Fatalf("BaseChecks = %v", got)
	}
}

func TestSearchScopeAndBase(t *testing.T) {
	s := open(t, fixture(t))
	p := search(t, s, query("(objectClass=inetOrgPerson)"))
	want := []string{"uid=alice,ou=people," + baseDN, "uid=bob,ou=people," + baseDN, "uid=carol,ou=deep,ou=people," + baseDN}
	if !equal(dns(p), want) || p.Truncated || p.Referrals != 0 {
		t.Fatalf("sub = %v (%+v)", dns(p), p)
	}

	q := query("(objectClass=*)")
	q.BaseDN = "ou=people," + baseDN
	q.Scope = ldapdir.ScopeOne
	if got := dns(search(t, s, q)); !equal(got, want[:2]) {
		t.Fatalf("one = %v", got)
	}

	q.BaseDN = "ou=nowhere," + baseDN
	if _, err := s.Search(context.Background(), q); !errors.Is(err, ldapdir.ErrBaseNotFound) {
		t.Fatalf("missing base = %v", err)
	}
	q.BaseDN = "=bad"
	if _, err := s.Search(context.Background(), q); !errors.Is(err, ldapdir.ErrBaseNotFound) {
		t.Fatalf("bad base = %v", err)
	}
}

func TestSearchFilters(t *testing.T) {
	d := fixture(t)
	d.Add(Entry{DN: "cn=svc," + baseDN, Attrs: map[string][][]byte{
		"objectClass":        Vals("user"),
		"userAccountControl": Vals("514"), // disabled (bit 2)
		"objectGUID":         {{0xff, 0x00, 0xfe}},
		"sn":                 Vals("Mmm"),
	}})
	d.Add(Entry{DN: "cn=user," + baseDN, Attrs: map[string][][]byte{
		"objectClass":        Vals("user"),
		"userAccountControl": Vals("512", "junk"),
	}})
	s := open(t, d)
	alice := "uid=alice,ou=people," + baseDN
	bob := "uid=bob,ou=people," + baseDN
	svc := "cn=svc," + baseDN
	usr := "cn=user," + baseDN
	cases := map[string][]string{
		"(mail=alice@example.test)":              {alice},
		"(MAIL=ALICE@EXAMPLE.TEST)":              {alice},
		"(uid~=bob)":                             {bob},
		"(&(objectClass=inetOrgPerson)(uid=a*))": {alice},
		"(|(uid=alice)(uid=bob))":                {alice, bob},
		"(&(mail=*)(!(uid=bob)))":                {alice},
		"(mail=*@example.test)":                  {alice, bob},
		"(mail=b*b*.test)":                       {bob},
		"(mail=*x*)":                             {alice, bob},
		"(mail=a*z)":                             nil,
		"(mail=*q*)":                             nil,
		"(mail=q*)":                              nil,
		"(uid>=bob)":                             {bob, "uid=carol,ou=deep,ou=people," + baseDN},
		"(uid<=alice)":                           {alice},
		"(uid=\\2a)":                             nil, // escaped '*' is a literal, not a wildcard
		"(uid:=alice)":                           {alice},
		"(userAccountControl:1.2.840.113556.1.4.803:=2)":                         {svc},
		"(userAccountControl:1.2.840.113556.1.4.804:=3)":                         {svc},
		"(userAccountControl:1.2.840.113556.1.4.803:=x)":                         nil,
		"(objectGUID=\\ff\\00\\fe)":                                              {svc},
		"(objectGUID=\\ff\\00\\ff)":                                              nil,
		"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))": {usr},
	}
	for f, want := range cases {
		q := query(f)
		q.Attributes = []string{"1.1"}
		if got := dns(search(t, s, q)); !equal(got, want) {
			t.Errorf("%s = %v, want %v", f, got, want)
		}
	}

	var de *ldapdir.DirectoryError
	if _, err := s.Search(context.Background(), query("(uid:1.2.3:=x)")); !errors.As(err, &de) || de.Code != 53 {
		t.Fatalf("unknown rule = %v", err)
	}
	for _, f := range []string{"", "uid=x", "(uid=x", "(uid=x))"} {
		if _, err := s.Search(context.Background(), query(f)); !errors.Is(err, ldapdir.ErrInvalidFilter) {
			t.Errorf("filter %q = %v", f, err)
		}
	}
}

func TestSearchAttributesProjectedAndCopied(t *testing.T) {
	d := fixture(t)
	s := open(t, d)
	q := query("(uid=alice)")
	q.Attributes = []string{"MAIL"}
	p := search(t, s, q)
	e := p.Entries[0]
	if len(e.Attrs) != 1 || string(e.Attrs["mail"][0]) != "Alice@Example.test" {
		t.Fatalf("attrs = %v", e.Attrs)
	}
	e.Attrs["mail"][0][0] = 'X'
	if got := search(t, s, q).Entries[0].Attrs["mail"][0][0]; got != 'A' {
		t.Fatal("results alias the stored entry")
	}
	q.Attributes = []string{"*"}
	if got := search(t, s, q).Entries[0].Attrs; len(got) != 4 || got["objectclass"] == nil {
		t.Fatalf("* = %v", got)
	}
}

func TestSearchAliases(t *testing.T) {
	d := fixture(t)
	d.AddAlias("uid=ghost,ou=people,"+baseDN, "uid=mallory,dc=other,dc=test")
	d.AddAlias("uid=dangling,ou=people,"+baseDN, "uid=nobody,dc=other,dc=test")
	s := open(t, d)
	q := query("(uid=*)")
	q.BaseDN = "ou=people," + baseDN
	// NeverDerefAliases honoured: the aliases are not persons and the
	// target outside the base never appears.
	for _, dn := range dns(search(t, s, q)) {
		if dn == "uid=mallory,dc=other,dc=test" {
			t.Fatal("alias dereferenced")
		}
	}
	q.Filter = "(objectClass=alias)"
	if got := dns(search(t, s, q)); len(got) != 2 {
		t.Fatalf("alias objects = %v", got)
	}

	// A misbehaving server dereferences anyway, leaking an out-of-base entry.
	d.SetDerefAliases(true)
	q.Filter = "(uid=mallory)"
	if got := dns(search(t, s, q)); !equal(got, []string{"uid=mallory,dc=other,dc=test"}) {
		t.Fatalf("deref = %v", got)
	}
	for _, c := range d.Searches() {
		if c.Deref != ldap.NeverDerefAliases {
			t.Fatalf("recorded deref = %d", c.Deref)
		}
	}
}

func TestSearchReferrals(t *testing.T) {
	d := fixture(t)
	d.AddReferral("ou=remote,"+baseDN, "ldap://remote.example.test/ou=remote")
	d.AddReferral("ou=far,ou=people,"+baseDN, "ldap://far.example.test/")
	s := open(t, d)
	p := search(t, s, query("(objectClass=*)"))
	if p.Referrals != 2 {
		t.Fatalf("Referrals = %d", p.Referrals)
	}
	for _, dn := range dns(p) {
		if dn == "ou=remote,"+baseDN {
			t.Fatal("referral returned as entry")
		}
	}
	q := query("(objectClass=*)")
	q.BaseDN = "ou=x,ou=remote," + baseDN
	var de *ldapdir.DirectoryError
	if _, err := s.Search(context.Background(), q); !errors.As(err, &de) || de.Code != 10 {
		t.Fatalf("search under referral = %v", err)
	}
}

func TestSearchLimits(t *testing.T) {
	d := fixture(t)
	s := open(t, d)
	q := query("(objectClass=inetOrgPerson)")

	q.SizeLimit = 2
	if p := search(t, s, q); len(p.Entries) != 2 || !p.Truncated {
		t.Fatalf("client size limit: %d %v", len(p.Entries), p.Truncated)
	}
	q.SizeLimit = 3
	if p := search(t, s, q); len(p.Entries) != 3 || p.Truncated {
		t.Fatalf("exact size: %d %v", len(p.Entries), p.Truncated)
	}

	d.SetServerSizeLimit(1)
	if p := search(t, s, q); len(p.Entries) != 1 || !p.Truncated {
		t.Fatalf("server size limit: %d %v", len(p.Entries), p.Truncated)
	}
	d.SetServerSizeLimit(0)

	d.SetTimeLimitAfter(0)
	if p := search(t, s, q); len(p.Entries) != 0 || !p.Truncated {
		t.Fatalf("time limit: %d %v", len(p.Entries), p.Truncated)
	}
	d.SetTimeLimitAfter(5) // more than match: no truncation
	if p := search(t, s, q); len(p.Entries) != 3 || p.Truncated {
		t.Fatalf("time limit not hit: %d %v", len(p.Entries), p.Truncated)
	}

	calls := d.Searches()
	last := calls[len(calls)-1]
	if last.WireSizeLimit != 4 || last.WireTimeLimit != 2 || last.Query.Filter != q.Filter {
		t.Fatalf("recorded = %+v", last)
	}
}

func TestSearchInvalidQueryRecorded(t *testing.T) {
	d := fixture(t)
	s := open(t, d)
	bad := []func(*ldapdir.Query){
		func(q *ldapdir.Query) { q.Scope = 7 },
		func(q *ldapdir.Query) { q.Attributes = nil },
		func(q *ldapdir.Query) { q.SizeLimit = 0 },
		func(q *ldapdir.Query) { q.TimeLimit = -1 },
	}
	for i, mut := range bad {
		q := query("(uid=*)")
		mut(&q)
		if _, err := s.Search(context.Background(), q); !errors.Is(err, ldapdir.ErrDirectory) {
			t.Errorf("case %d = %v", i, err)
		}
	}
	if n := len(d.Searches()); n != len(bad) {
		t.Fatalf("recorded %d searches", n)
	}
}

func TestRecordedQueryIsACopy(t *testing.T) {
	d := fixture(t)
	s := open(t, d)
	q := query("(uid=*)")
	search(t, s, q)
	q.Attributes[0] = "changed"
	got := d.Searches()
	got[0].Query.Attributes[1] = "changed"
	if a := d.Searches()[0].Query.Attributes; a[0] != "uid" || a[1] != "mail" {
		t.Fatalf("recorded attributes aliased: %v", a)
	}
}

func TestInjectedErrors(t *testing.T) {
	d := fixture(t)
	d.InjectError(OpOpen, ldapdir.ErrTargetRefused, ldapdir.ErrTLS)
	for _, want := range []error{ldapdir.ErrTargetRefused, ldapdir.ErrTLS} {
		if _, err := d.Open(context.Background(), ldaps); !errors.Is(err, want) {
			t.Fatalf("Open = %v, want %v", err, want)
		}
	}
	s := open(t, d) // queue drained

	d.InjectError(OpBind, nil, ldapdir.ErrUnreachable)
	if err := s.Bind(context.Background(), bindDN, []byte(bindPW)); err != nil {
		t.Fatalf("nil injection must pass through: %v", err)
	}
	if err := s.Bind(context.Background(), bindDN, []byte(bindPW)); !errors.Is(err, ldapdir.ErrUnreachable) {
		t.Fatalf("Bind = %v", err)
	}

	d.InjectError(OpBaseExists, ldapdir.ErrBaseNotFound)
	if err := s.BaseExists(context.Background(), baseDN); !errors.Is(err, ldapdir.ErrBaseNotFound) {
		t.Fatalf("BaseExists = %v", err)
	}
	if err := s.BaseExists(context.Background(), baseDN); err != nil {
		t.Fatalf("BaseExists after drain = %v", err)
	}

	d.InjectError(OpSearch, &ldapdir.DirectoryError{Code: 80})
	if _, err := s.Search(context.Background(), query("(uid=*)")); !errors.Is(err, ldapdir.ErrDirectory) {
		t.Fatalf("Search = %v", err)
	}

	// An injected timeout kills the session like a real one.
	d.InjectError(OpSearch, ldapdir.ErrTimeout)
	if _, err := s.Search(context.Background(), query("(uid=*)")); !errors.Is(err, ldapdir.ErrTimeout) {
		t.Fatalf("Search = %v", err)
	}
	if _, err := s.Search(context.Background(), query("(uid=*)")); !errors.Is(err, ldapdir.ErrUnreachable) {
		t.Fatalf("Search after timeout = %v", err)
	}
	if n := len(d.Opens()); n != 3 {
		t.Fatalf("Opens = %d", n)
	}
}

func TestDelayHonoursDeadline(t *testing.T) {
	d := fixture(t)
	d.SetDelay(10 * time.Millisecond)
	s := open(t, d)
	if err := s.Bind(context.Background(), bindDN, []byte(bindPW)); err != nil {
		t.Fatalf("delayed Bind = %v", err)
	}

	d.SetDelay(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Search(ctx, query("(uid=*)")); !errors.Is(err, ldapdir.ErrTimeout) {
		t.Fatalf("Search = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("deadline not honoured")
	}
	if err := s.BaseExists(context.Background(), baseDN); !errors.Is(err, ldapdir.ErrUnreachable) {
		t.Fatalf("session usable after timeout: %v", err)
	}
}

func TestAddPanicsOnInvalidDN(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	New().Add(Entry{DN: "=bad"})
}
