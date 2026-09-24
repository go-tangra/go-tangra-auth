package directory

// Tests first for search (T041, US2; research D6/D7/D14): the query actually
// sent (effective filter (&base user), connection or narrowed base,
// NeverDerefAliases, mapped attributes only, size/time limits), refusal of
// invalid filters/bases before any directory call, out-of-base entries and
// referrals, truncation, timeouts, preview statuses, the directory_searched
// audit event, the shared per-tenant rate limit and tenant isolation.
//
// The fixture is ttSetup (test_test.go); helpers here carry an "st" prefix.

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/ldapdir/ldapfake"
	"github.com/go-freya/freya/services/auth/internal/store"
)

const (
	stDevDN   = "ou=Dev," + ttBaseDN
	stSalesDN = "ou=Sales,dc=example,dc=test"

	stAliceDN = "uid=alice," + ttBaseDN
	stBobDN   = "uid=bob," + stDevDN
	stCarolDN = "uid=carol," + ttBaseDN
	stMalDN   = "uid=mallory," + stSalesDN

	stUserActive   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d01"
	stUserImported = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d02"
	stUserRenamed  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d03"
	stUserAccepted = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d04"
	stUserOther    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d05"
)

// stPerson is an inetOrgPerson-like entry with the OpenLDAP mapping of the
// ttSetup connection (entryUUID/mail/displayName/givenName/sn).
func stPerson(dn, uuid, mail, display, first, last, dept string) ldapfake.Entry {
	attrs := map[string][][]byte{
		"objectClass": ldapfake.Vals("top", "person", "inetOrgPerson"),
		"entryUUID":   ldapfake.Vals(uuid),
		"displayName": ldapfake.Vals(display),
		"givenName":   ldapfake.Vals(first),
		"sn":          ldapfake.Vals(last),
		"department":  ldapfake.Vals(dept),
		// Never requested: only mapped attributes are asked for.
		"jpegPhoto": {make([]byte, 64)},
	}
	if mail != "" {
		attrs["mail"] = ldapfake.Vals(mail)
	}
	return ldapfake.Entry{DN: dn, Attrs: attrs}
}

// stPeople adds the standard tree: alice and carol (no mail) directly under
// the connection base, bob under ou=Dev, a printer (not a person) under the
// base, and mallory in ou=Sales outside the base.
func stPeople(f *ttFixture) {
	f.dir.Add(ldapfake.Entry{DN: stDevDN, Attrs: map[string][][]byte{"objectClass": ldapfake.Vals("organizationalUnit")}})
	f.dir.Add(ldapfake.Entry{DN: stSalesDN, Attrs: map[string][][]byte{"objectClass": ldapfake.Vals("organizationalUnit")}})
	f.dir.Add(stPerson(stAliceDN, "uuid-alice", "Alice@Example.test", "Alice Liddell", "Alice", "Liddell", "Eng"))
	f.dir.Add(stPerson(stBobDN, "uuid-bob", "bob@example.test", "Bob Builder", "Bob", "Builder", "Dev"))
	f.dir.Add(stPerson(stCarolDN, "uuid-carol", "", "Carol Nomail", "Carol", "Nomail", "Eng"))
	f.dir.Add(stPerson(stMalDN, "uuid-mallory", "mallory@example.test", "Mallory", "Mal", "Lory", "Eng"))
	f.dir.Add(ldapfake.Entry{DN: "cn=printer," + ttBaseDN, Attrs: map[string][][]byte{
		"objectClass": ldapfake.Vals("device"), "cn": ldapfake.Vals("printer"),
		"entryUUID": ldapfake.Vals("uuid-printer"), "mail": ldapfake.Vals("printer@example.test"), "department": ldapfake.Vals("Eng"),
	}})
}

func stSetup(t *testing.T, o ttOpts) *ttFixture {
	t.Helper()
	f := ttSetup(t, o)
	stPeople(f)
	return f
}

// configure rewrites the ttTenant connection.
func (f *ttFixture) configure(t *testing.T, mutate func(*store.DirectoryConnection)) {
	t.Helper()
	c := f.conn(t, ttTenant, ttConnID)
	mutate(&c)
	if err := f.ms.UpdateDirectoryConnection(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func (f *ttFixture) search(req SearchRequest) (SearchResult, error) {
	return f.svc.Search(context.Background(), ttAdmin(ttTenant), ttTenant, ttConnID, req)
}

func (f *ttFixture) mustSearch(t *testing.T, req SearchRequest) SearchResult {
	t.Helper()
	res, err := f.search(req)
	if err != nil {
		t.Fatalf("search %+v: %v", req, err)
	}
	ttNoSecret(t, "search result", res)
	if res.Items == nil {
		t.Fatal("items must be an empty slice, never nil (JSON [])")
	}
	if n := f.dir.OpenSessions(); n != 0 {
		t.Fatalf("%d directory sessions left open", n)
	}
	return res
}

func (f *ttFixture) lastSearch(t *testing.T) ldapfake.SearchCall {
	t.Helper()
	s := f.dir.Searches()
	if len(s) == 0 {
		t.Fatal("no search reached the directory")
	}
	return s[len(s)-1]
}

// noDirectoryCalls fails when anything reached the directory.
func (f *ttFixture) noDirectoryCalls(t *testing.T) {
	t.Helper()
	if o, b, c, s := len(f.dir.Opens()), len(f.dir.Binds()), len(f.dir.BaseChecks()), len(f.dir.Searches()); o+b+c+s != 0 {
		t.Fatalf("directory calls: opens=%d binds=%d base checks=%d searches=%d, want none", o, b, c, s)
	}
}

// stCanon is the canonical (compiled then decompiled) form of a valid filter.
func stCanon(t *testing.T, s string) string {
	t.Helper()
	p, err := ldap.CompileFilter(s)
	if err != nil {
		t.Fatalf("test filter does not compile: %v", err)
	}
	out, err := ldap.DecompileFilter(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func stUIDs(res *SearchResult) []string {
	out := make([]string, 0, len(res.Items))
	for i := range res.Items {
		out = append(out, res.Items[i].UID)
	}
	sort.Strings(out)
	return out
}

func stEqual(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func stSameDN(a, b string) bool {
	x, err1 := ldap.ParseDN(a)
	y, err2 := ldap.ParseDN(b)
	return err1 == nil && err2 == nil && x.EqualFold(y)
}

func (f *ttFixture) searched(t *testing.T) []store.AuditRow {
	t.Helper()
	return f.events(audit.DirectorySearched)
}

func TestSearchQueryShape(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.configure(t, func(c *store.DirectoryConnection) { c.BaseFilter = "(objectClass=person)" })

	res := f.mustSearch(t, SearchRequest{Filter: "(department=Eng)"})

	want := "(&" + stCanon(t, "(objectClass=person)") + stCanon(t, "(department=Eng)") + ")"
	if res.EffectiveFilter != want {
		t.Fatalf("effective_filter %q, want %q", res.EffectiveFilter, want)
	}
	if len(f.dir.Opens()) != 1 || len(f.dir.Searches()) != 1 {
		t.Fatalf("opens=%d searches=%d, want exactly one each", len(f.dir.Opens()), len(f.dir.Searches()))
	}
	if p := f.dir.Opens()[0]; p.URL != ttURL || p.TLSMode != ldapdir.TLSModeLDAPS {
		t.Fatalf("open params url=%q tls_mode=%q", p.URL, p.TLSMode)
	}
	binds := f.dir.Binds()
	if len(binds) != 1 || binds[0].DN != ttBindDN || binds[0].Password != ttStoredPW {
		t.Fatal("search must bind once as the connection's bind DN with its stored password")
	}

	q := f.lastSearch(t)
	if q.Query.Filter != want {
		t.Fatalf("filter sent %q, want %q", q.Query.Filter, want)
	}
	if q.Query.BaseDN != ttBaseDN {
		t.Fatalf("base sent %q, want the connection base %q", q.Query.BaseDN, ttBaseDN)
	}
	if q.Query.Scope != ldapdir.ScopeSub {
		t.Fatalf("default scope %v, want subtree", q.Query.Scope)
	}
	if q.Deref != ldap.NeverDerefAliases {
		t.Fatalf("deref %d, want NeverDerefAliases", q.Deref)
	}
	if !stEqual(q.Query.Attributes, []string{"entryUUID", "mail", "displayName", "givenName", "sn"}) {
		t.Fatalf("attributes %v, want only the mapped ones", q.Query.Attributes)
	}
	// Query.SizeLimit is the connection limit; the client puts limit+1 on
	// the wire so that truncation is detectable (D7).
	if q.Query.SizeLimit != 500 || q.WireSizeLimit != 501 {
		t.Fatalf("size limit %d (wire %d), want 500 (wire 501)", q.Query.SizeLimit, q.WireSizeLimit)
	}
	if q.Query.TimeLimit != 15*time.Second || q.WireTimeLimit != 15 {
		t.Fatalf("time limit %v (wire %d), want 15s", q.Query.TimeLimit, q.WireTimeLimit)
	}

	// Only alice: carol matches too but is invalid (no mail) and still
	// listed; the printer fails the base filter; mallory is outside the base.
	if got := stUIDs(&res); !stEqual(got, []string{"uuid-alice", "uuid-carol"}) {
		t.Fatalf("uids %v", got)
	}
	if res.Truncated || res.OutOfScope != 0 {
		t.Fatalf("truncated=%v out_of_scope=%d", res.Truncated, res.OutOfScope)
	}
}

// Nothing the administrator types can widen the search beyond the base
// filter (SR-003, SC-005): the effective filter is always (&base user).
func TestSearchEffectiveFilterConjunction(t *testing.T) {
	cases := []struct {
		name, base, user string
		wantBase         string // canonical base half
		wantUser         string // canonical user half
		uids             []string
	}{
		{"both", "(objectClass=person)", "(department=Dev)", "(objectClass=person)", "(department=Dev)", []string{"uuid-bob"}},
		{"empty user filter", "(objectClass=person)", "", "(objectClass=person)", "(objectClass=*)", []string{"uuid-alice", "uuid-bob", "uuid-carol"}},
		{"empty base filter", "", "(department=Dev)", "(objectClass=*)", "(department=Dev)", []string{"uuid-bob"}},
		{"widening or", "(objectClass=person)", "(|(objectClass=*)(cn=printer))", "(objectClass=person)", "(|(objectClass=*)(cn=printer))", []string{"uuid-alice", "uuid-bob", "uuid-carol"}},
		{"not base", "(objectClass=person)", "(!(objectClass=person))", "(objectClass=person)", "(!(objectClass=person))", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			f.configure(t, func(c *store.DirectoryConnection) { c.BaseFilter = tc.base })
			res := f.mustSearch(t, SearchRequest{Filter: tc.user})
			want := "(&" + stCanon(t, tc.wantBase) + stCanon(t, tc.wantUser) + ")"
			if res.EffectiveFilter != want || f.lastSearch(t).Query.Filter != want {
				t.Fatalf("effective %q / sent %q, want %q", res.EffectiveFilter, f.lastSearch(t).Query.Filter, want)
			}
			if got := stUIDs(&res); !stEqual(got, tc.uids) {
				t.Fatalf("uids %v, want %v", got, tc.uids)
			}
		})
	}
}

// The user filter is sent in canonical form, never byte-for-byte (D6).
func TestSearchCanonicalFilter(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.configure(t, func(c *store.DirectoryConnection) { c.BaseFilter = "(objectClass=person)" })
	res := f.mustSearch(t, SearchRequest{Filter: `(displayName=Alice\20Liddell)`})
	want := "(&(objectClass=person)" + stCanon(t, `(displayName=Alice\20Liddell)`) + ")"
	if res.EffectiveFilter != want {
		t.Fatalf("effective %q, want %q", res.EffectiveFilter, want)
	}
	if got := stUIDs(&res); !stEqual(got, []string{"uuid-alice"}) {
		t.Fatalf("uids %v", got)
	}
}

func TestSearchBaseAndScope(t *testing.T) {
	cases := []struct {
		name  string
		req   SearchRequest
		base  string
		scope ldapdir.Scope
		uids  []string
	}{
		{"connection base subtree", SearchRequest{Filter: "(objectClass=person)", Scope: "sub"}, ttBaseDN, ldapdir.ScopeSub, []string{"uuid-alice", "uuid-bob", "uuid-carol"}},
		{"connection base one level", SearchRequest{Filter: "(objectClass=person)", Scope: "one"}, ttBaseDN, ldapdir.ScopeOne, []string{"uuid-alice", "uuid-carol"}},
		{"narrowed base", SearchRequest{Filter: "(objectClass=person)", Base: stDevDN}, stDevDN, ldapdir.ScopeSub, []string{"uuid-bob"}},
		{"narrowed base other case", SearchRequest{Filter: "(objectClass=person)", Base: "OU=dev,OU=engineering,DC=Example,DC=test"}, stDevDN, ldapdir.ScopeSub, []string{"uuid-bob"}},
		{"base equal to connection base", SearchRequest{Filter: "(objectClass=person)", Base: ttBaseDN, Scope: "one"}, ttBaseDN, ldapdir.ScopeOne, []string{"uuid-alice", "uuid-carol"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			res := f.mustSearch(t, tc.req)
			q := f.lastSearch(t)
			if !stSameDN(q.Query.BaseDN, tc.base) {
				t.Fatalf("base sent %q, want %q", q.Query.BaseDN, tc.base)
			}
			if q.Query.Scope != tc.scope {
				t.Fatalf("scope %v, want %v", q.Query.Scope, tc.scope)
			}
			if got := stUIDs(&res); !stEqual(got, tc.uids) {
				t.Fatalf("uids %v, want %v", got, tc.uids)
			}
		})
	}
}

// Only mapped attributes are requested; empty optional mappings are left
// out, and an AD objectGUID is decoded to the canonical GUID string.
func TestSearchMappedAttributesOnly(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.configure(t, func(c *store.DirectoryConnection) {
		c.Kind = "active_directory"
		c.AttrUID, c.AttrEmail, c.AttrDisplayName, c.AttrFirstName, c.AttrLastName = "objectGUID", "mail", "displayName", "", ""
	})
	guid := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	f.dir.Add(ldapfake.Entry{DN: "cn=Dana Scully," + ttBaseDN, Attrs: map[string][][]byte{
		"objectClass": ldapfake.Vals("top", "person", "user"), "objectGUID": {guid},
		"mail": ldapfake.Vals("dana@example.test"), "displayName": ldapfake.Vals("Dana Scully"),
		"givenName": ldapfake.Vals("Dana"), "sn": ldapfake.Vals("Scully"),
	}})
	res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=user)"})
	if got := f.lastSearch(t).Query.Attributes; !stEqual(got, []string{"objectGUID", "mail", "displayName"}) {
		t.Fatalf("attributes %v, want [objectGUID mail displayName]", got)
	}
	if len(res.Items) != 1 {
		t.Fatalf("items %+v", res.Items)
	}
	it := res.Items[0]
	if it.UID != "03020100-0504-0706-0809-0a0b0c0d0e0f" || it.Status != "new" || it.Email != "dana@example.test" || it.DisplayName != "Dana Scully" {
		t.Fatalf("item %+v", it)
	}
	if it.FirstName != "" || it.LastName != "" {
		t.Fatalf("unmapped names must stay empty, got %q %q", it.FirstName, it.LastName)
	}
}

// Invalid filters, bases and scopes are refused before anything reaches the
// directory (US2-2, D6).
func TestSearchRefusedBeforeDirectory(t *testing.T) {
	long := "(|" + strings.Repeat("(cn=abcdefghijklmnopqrstuvwxyz)", 140) + ")" // > 4 KiB
	cases := []struct {
		name   string
		req    SearchRequest
		want   error
		reason string
	}{
		{"unbalanced", SearchRequest{Filter: "(cn=a"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"no parens", SearchRequest{Filter: "cn=a"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"injection close and or", SearchRequest{Filter: "(department=Eng))(|(objectClass=*)"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"trailing garbage", SearchRequest{Filter: "(cn=a)(cn=b)"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"too long", SearchRequest{Filter: long}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"dn extensible match", SearchRequest{Filter: "(ou:dn:=Sales)"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"nul", SearchRequest{Filter: "(cn=a\x00)"}, ldapdir.ErrInvalidFilter, "invalid_filter"},
		{"base outside", SearchRequest{Base: stSalesDN}, ldapdir.ErrInvalidBase, "invalid_base"},
		{"base parent", SearchRequest{Base: "dc=example,dc=test"}, ldapdir.ErrInvalidBase, "invalid_base"},
		{"base suffix trick", SearchRequest{Base: "ou=Engineering,dc=evilexample,dc=test"}, ldapdir.ErrInvalidBase, "invalid_base"},
		{"base not a dn", SearchRequest{Base: "not a dn"}, ldapdir.ErrInvalidBase, "invalid_base"},
		{"base empty value", SearchRequest{Base: "cn=," + ttBaseDN}, ldapdir.ErrInvalidBase, "invalid_base"},
		{"scope base", SearchRequest{Scope: "base"}, ErrValidation, ""},
		{"scope children", SearchRequest{Scope: "children"}, ErrValidation, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			_, err := f.search(tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			ttNoSecretErr(t, "search", err)
			f.noDirectoryCalls(t)
			if tc.reason == "" {
				return
			}
			if r := ldapdir.Reason(err); r != tc.reason {
				t.Fatalf("reason %q, want %q", r, tc.reason)
			}
			rows := f.searched(t)
			if len(rows) != 1 || rows[0].Outcome != "refused" || rows[0].Reason != tc.reason || rows[0].TenantID != ttTenant {
				t.Fatalf("directory_searched rows %+v, want one refused %s", rows, tc.reason)
			}
		})
	}
}

// stHostile decorates a directory so every search also returns extra
// entries, as a hostile or misconfigured server could.
type stHostile struct {
	ldapdir.Directory
	extra []ldapdir.RawEntry
}

func (h *stHostile) Open(ctx context.Context, p ldapdir.ConnParams) (ldapdir.Session, error) {
	s, err := h.Directory.Open(ctx, p)
	if err != nil {
		return nil, err
	}
	return &stHostileSession{Session: s, extra: h.extra}, nil
}

type stHostileSession struct {
	ldapdir.Session
	extra []ldapdir.RawEntry
}

//nolint:gocritic // hugeParam: Query is passed by value per ldapdir.Session.
func (s *stHostileSession) Search(ctx context.Context, q ldapdir.Query) (ldapdir.Page, error) {
	p, err := s.Session.Search(ctx, q)
	if err != nil {
		return p, err
	}
	p.Entries = append(p.Entries, s.extra...)
	return p, nil
}

func stRaw(dn, uuid, mail string) ldapdir.RawEntry {
	return ldapdir.RawEntry{DN: dn, Attrs: map[string][][]byte{
		"entryuuid": ldapfake.Vals(uuid), "mail": ldapfake.Vals(mail), "displayname": ldapfake.Vals("Intruder"),
	}}
}

// Entries whose DN is not within the (narrowed) base are dropped and counted
// (D6): alias targets from a server that dereferences despite
// NeverDerefAliases, and entries a hostile server adds.
func TestSearchDropsOutOfBase(t *testing.T) {
	extra := []ldapdir.RawEntry{
		stRaw("uid=eve,"+stSalesDN, "uuid-eve", "eve@example.test"),
		stRaw("uid=trent,ou=Engineering,dc=evilexample,dc=test", "uuid-trent", "trent@example.test"),
	}
	f := stSetup(t, ttOpts{wrap: func(d ldapdir.Directory) ldapdir.Directory { return &stHostile{Directory: d, extra: extra} }})
	f.dir.SetDerefAliases(true)
	f.dir.AddAlias("cn=alias-mallory,"+ttBaseDN, stMalDN)

	res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)"})
	if f.lastSearch(t).Deref != ldap.NeverDerefAliases {
		t.Fatal("search must request NeverDerefAliases")
	}
	if got := stUIDs(&res); !stEqual(got, []string{"uuid-alice", "uuid-bob", "uuid-carol"}) {
		t.Fatalf("uids %v", got)
	}
	if res.OutOfScope != 3 {
		t.Fatalf("out_of_scope %d, want 3 (alias target + 2 injected)", res.OutOfScope)
	}
	js, _ := json.Marshal(res)
	for _, leak := range []string{"mallory", "eve", "trent", "evilexample", "Sales"} {
		if strings.Contains(string(js), leak) {
			t.Fatalf("result carries out-of-base entry data %q", leak)
		}
	}

	t.Run("narrowed base", func(t *testing.T) {
		f := stSetup(t, ttOpts{wrap: func(d ldapdir.Directory) ldapdir.Directory {
			// alice is under the connection base but not under ou=Dev.
			return &stHostile{Directory: d, extra: []ldapdir.RawEntry{stRaw(stAliceDN, "uuid-alice", "alice@example.test")}}
		}})
		res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)", Base: stDevDN})
		if got := stUIDs(&res); !stEqual(got, []string{"uuid-bob"}) || res.OutOfScope != 1 {
			t.Fatalf("uids %v out_of_scope %d, want [uuid-bob] and 1", got, res.OutOfScope)
		}
	})

	t.Run("invalid dn", func(t *testing.T) {
		f := stSetup(t, ttOpts{wrap: func(d ldapdir.Directory) ldapdir.Directory {
			return &stHostile{Directory: d, extra: []ldapdir.RawEntry{stRaw("not a dn", "uuid-x", "x@example.test"), stRaw("", "uuid-y", "y@example.test")}}
		}})
		res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)"})
		if got := stUIDs(&res); !stEqual(got, []string{"uuid-alice", "uuid-bob", "uuid-carol"}) || res.OutOfScope != 2 {
			t.Fatalf("uids %v out_of_scope %d", got, res.OutOfScope)
		}
	})
}

// Referrals are never followed and are not an error (SR-003).
func TestSearchIgnoresReferrals(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.dir.AddReferral("ou=Remote,"+ttBaseDN, "ldap://evil.example.test/ou=People,dc=evil,dc=test")
	res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)"})
	if got := stUIDs(&res); !stEqual(got, []string{"uuid-alice", "uuid-bob", "uuid-carol"}) {
		t.Fatalf("uids %v", got)
	}
	if res.OutOfScope != 0 || res.Truncated {
		t.Fatalf("out_of_scope %d truncated %v", res.OutOfScope, res.Truncated)
	}
	if len(f.dir.Opens()) != 1 || len(f.dir.Searches()) != 1 {
		t.Fatalf("opens=%d searches=%d: a referral must not be chased", len(f.dir.Opens()), len(f.dir.Searches()))
	}
	if strings.Contains(res.EffectiveFilter, "evil") {
		t.Fatal("referral leaked into the result")
	}
}

func TestSearchTruncation(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(*ttFixture)
		size      int
		items     int
		truncated bool
	}{
		{"within limits", func(*ttFixture) {}, 500, 3, false},
		{"exactly the size limit", func(*ttFixture) {}, 3, 3, false},
		{"connection size limit", func(*ttFixture) {}, 2, 2, true},
		{"server size limit", func(f *ttFixture) { f.dir.SetServerSizeLimit(1) }, 500, 1, true},
		{"server time limit", func(f *ttFixture) { f.dir.SetTimeLimitAfter(1) }, 500, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			f.configure(t, func(c *store.DirectoryConnection) { c.SizeLimit, c.TimeLimitSeconds = tc.size, 7 })
			tc.setup(f)
			res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)"})
			if len(res.Items) != tc.items || res.Truncated != tc.truncated {
				t.Fatalf("items %d truncated %v, want %d %v", len(res.Items), res.Truncated, tc.items, tc.truncated)
			}
			q := f.lastSearch(t)
			if q.Query.SizeLimit != tc.size || q.WireSizeLimit != tc.size+1 {
				t.Fatalf("size limit %d (wire %d), want %d (wire %d)", q.Query.SizeLimit, q.WireSizeLimit, tc.size, tc.size+1)
			}
			if q.Query.TimeLimit != 7*time.Second {
				t.Fatalf("time limit %v, want 7s", q.Query.TimeLimit)
			}
			rows := f.searched(t)
			if len(rows) != 1 {
				t.Fatalf("directory_searched rows = %d", len(rows))
			}
			if d := ttDetails(t, &rows[0]); d["truncated"] != tc.truncated || d["count"] != float64(tc.items) {
				t.Fatalf("audit details truncated=%v count=%v", d["truncated"], d["count"])
			}
		})
	}
}

// Directory failures are closed-vocabulary errors (HTTP 502/504), audited
// as failed, with the session always closed.
func TestSearchDirectoryFailures(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*ldapfake.Directory)
		reason string
	}{
		{"unreachable", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpOpen, ldapdir.ErrUnreachable) }, "unreachable"},
		{"tls", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpOpen, ldapdir.ErrTLS) }, "tls_failed"},
		{"target refused at dial", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpOpen, ldapdir.ErrTargetRefused) }, "target_refused"},
		{"bind", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpBind, ldapdir.ErrInvalidCredentials) }, "invalid_credentials"},
		{"search timeout", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpSearch, ldapdir.ErrTimeout) }, "timeout"},
		{"server error", func(d *ldapfake.Directory) { d.InjectError(ldapfake.OpSearch, &ldapdir.DirectoryError{Code: 80}) }, "directory_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			tc.inject(f.dir)
			res, err := f.search(SearchRequest{Filter: "(objectClass=person)"})
			if err == nil {
				t.Fatalf("want an error, got %+v", res)
			}
			if r := ldapdir.Reason(err); r != tc.reason {
				t.Fatalf("reason %q, want %q", r, tc.reason)
			}
			ttNoSecretErr(t, "search", err)
			if len(res.Items) != 0 {
				t.Fatal("a failed search returns no items")
			}
			if n := f.dir.OpenSessions(); n != 0 {
				t.Fatalf("%d sessions left open", n)
			}
			if tc.reason == "invalid_credentials" && len(f.dir.Searches()) != 0 {
				t.Fatal("no search after a failed bind")
			}
			rows := f.searched(t)
			if len(rows) != 1 || rows[0].Outcome != "failed" || rows[0].Reason != tc.reason {
				t.Fatalf("directory_searched rows %+v, want one failed %s", rows, tc.reason)
			}
		})
	}
}

// A search that outlives its deadline stops with timeout.
func TestSearchTimeout(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.dir.SetDelay(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := f.svc.Search(ctx, ttAdmin(ttTenant), ttTenant, ttConnID, SearchRequest{Filter: "(objectClass=person)"})
	if !errors.Is(err, ldapdir.ErrTimeout) || ldapdir.Reason(err) != "timeout" {
		t.Fatalf("err %v, want timeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("search did not stop at the deadline")
	}
	if n := f.dir.OpenSessions(); n != 0 {
		t.Fatalf("%d sessions left open", n)
	}
}

func TestSearchPreviewStatuses(t *testing.T) {
	f := stSetup(t, ttOpts{})
	ctx := context.Background()
	d := f.dir
	d.Add(stPerson("uid=dave,"+ttBaseDN, "uuid-dave", "dave@example.test", "Dave", "Dave", "Imported", "Eng"))
	d.Add(stPerson("uid=erin,"+ttBaseDN, "uuid-erin", "erin.new@example.test", "Erin", "Erin", "Renamed", "Eng"))
	d.Add(stPerson("uid=frank,"+ttBaseDN, "uuid-frank", "frank@example.test", "Frank", "Frank", "Accepted", "Eng"))
	d.Add(stPerson("uid=grace,"+ttBaseDN, "uuid-grace", "not-an-email", "Grace", "Grace", "Badmail", "Eng"))
	heidi := stPerson("uid=heidi,"+ttBaseDN, "uuid-heidi", "heidi@example.test", "Heidi", "Heidi", "Multi", "Eng")
	heidi.Attrs["entryUUID"] = ldapfake.Vals("uuid-heidi-1", "uuid-heidi-2")
	d.Add(heidi)
	d.Add(stPerson("uid=ivan,"+ttBaseDN, "uuid-ivan", "ivan@example.test", strings.Repeat("I", 101), "Ivan", "Long", "Eng"))

	now := time.Now()
	connID := ttConnID
	// bob is already a platform user (case-insensitive e-mail match).
	f.ms.AddUser(store.User{ID: stUserActive, TenantID: ttTenant, Email: "bob@example.test", Status: "active", CreatedAt: now})
	// dave was imported from this connection.
	f.ms.AddUser(store.User{ID: stUserImported, TenantID: ttTenant, Email: "dave@example.test", Status: "imported", CreatedAt: now})
	// erin was imported under an older e-mail: the uid link decides.
	f.ms.AddUser(store.User{ID: stUserRenamed, TenantID: ttTenant, Email: "erin.old@example.test", Status: "imported", CreatedAt: now})
	// frank was imported, activated and has accepted: now a platform user.
	f.ms.AddUser(store.User{ID: stUserAccepted, TenantID: ttTenant, Email: "frank@example.test", Status: "active", CreatedAt: now})
	// alice exists only in the other tenant: still new here.
	f.ms.AddUser(store.User{ID: stUserOther, TenantID: ttOther, Email: "alice@example.test", Status: "active", CreatedAt: now})
	for uid, user := range map[string]string{"uuid-dave": stUserImported, "uuid-erin": stUserRenamed, "uuid-frank": stUserAccepted} {
		if err := f.ms.UpsertLink(ctx, store.DirectoryLink{UserID: user, TenantID: ttTenant, ConnectionID: &connID, ConnectionName: "Corp LDAP",
			DirectoryUID: uid, DirectoryDN: "uid=x," + ttBaseDN, FirstImportedAt: now, LastImportedAt: now}); err != nil {
			t.Fatal(err)
		}
	}

	res := f.mustSearch(t, SearchRequest{Filter: "(objectClass=person)"})

	type want struct{ uid, status, userID, reason string }
	wants := map[string]want{
		stAliceDN:               {"uuid-alice", "new", "", ""},
		stBobDN:                 {"uuid-bob", "existing_user", stUserActive, ""},
		stCarolDN:               {"uuid-carol", "invalid", "", "no_email"},
		"uid=dave," + ttBaseDN:  {"uuid-dave", "imported", stUserImported, ""},
		"uid=erin," + ttBaseDN:  {"uuid-erin", "imported", stUserRenamed, ""},
		"uid=frank," + ttBaseDN: {"uuid-frank", "existing_user", stUserAccepted, ""},
		"uid=grace," + ttBaseDN: {"uuid-grace", "invalid", "", "invalid_email"},
		"uid=heidi," + ttBaseDN: {"", "invalid", "", "multi_valued_uid"},
		"uid=ivan," + ttBaseDN:  {"uuid-ivan", "invalid", "", "value_too_long"},
	}
	if len(res.Items) != len(wants) {
		t.Fatalf("items %d, want %d: %+v", len(res.Items), len(wants), res.Items)
	}
	for i := range res.Items {
		it := &res.Items[i]
		w, ok := wants[it.DN]
		if !ok {
			t.Fatalf("unexpected item %q", it.DN)
		}
		if it.UID != w.uid || it.Status != w.status || it.UserID != w.userID || it.Reason != w.reason {
			t.Errorf("%s: uid=%q status=%q user_id=%q reason=%q, want %+v", it.DN, it.UID, it.Status, it.UserID, it.Reason, w)
		}
		if it.DN == stAliceDN && (it.Email != "alice@example.test" || it.DisplayName != "Alice Liddell" || it.FirstName != "Alice" || it.LastName != "Liddell") {
			t.Errorf("alice mapped as %+v", *it)
		}
	}
	// Previewing is read-only: it creates no users or links.
	if m, _ := f.ms.UsersByEmails(ctx, ttTenant, []string{"alice@example.test"}); len(m) != 0 {
		t.Fatal("search must not create users")
	}
	if l, _ := f.ms.LinksByUIDs(ctx, ttTenant, ttConnID, []string{"uuid-alice"}); len(l) != 0 {
		t.Fatal("search must not create links")
	}
}

func TestSearchAudit(t *testing.T) {
	f := stSetup(t, ttOpts{})
	f.configure(t, func(c *store.DirectoryConnection) { c.BaseFilter = "(objectClass=person)" })
	res := f.mustSearch(t, SearchRequest{Filter: "(department=Dev)", Base: stDevDN, Scope: "one"})
	if len(res.Items) != 1 {
		t.Fatalf("items %+v", res.Items)
	}
	rows := f.searched(t)
	if len(rows) != 1 {
		t.Fatalf("directory_searched rows = %d", len(rows))
	}
	r := &rows[0]
	if r.TenantID != ttTenant || r.Outcome != "ok" || r.ActorUserID == nil || *r.ActorUserID != "u-admin" {
		t.Fatalf("row tenant=%s outcome=%s actor=%v", r.TenantID, r.Outcome, r.ActorUserID)
	}
	if r.SubjectKind != "directory_connection" || r.SubjectID == nil || *r.SubjectID != ttConnID {
		t.Fatalf("subject %s/%v", r.SubjectKind, r.SubjectID)
	}
	d := ttDetails(t, r)
	if d["filter"] != stCanon(t, "(department=Dev)") {
		t.Fatalf("details filter %v, want the canonical user filter", d["filter"])
	}
	if d["count"] != float64(1) || d["truncated"] != false || d["scope"] != "one" {
		t.Fatalf("details count=%v truncated=%v scope=%v", d["count"], d["truncated"], d["scope"])
	}
	if b, _ := d["base"].(string); !stSameDN(b, stDevDN) {
		t.Fatalf("details base %v, want the narrowed base", d["base"])
	}
	// Never entries: no uid, DN, e-mail or name of a directory person.
	for _, leak := range []string{"uuid-bob", "uid=bob", "bob@example.test", "Bob", "Builder"} {
		if strings.Contains(string(r.Details), leak) || strings.Contains(r.Reason, leak) {
			t.Fatalf("audit details carry directory entry data %q", leak)
		}
	}
	for _, k := range []string{"items", "entries", "uids", "emails"} {
		if _, ok := d[k]; ok {
			t.Fatalf("audit details carry %q", k)
		}
	}
	f.noSecretInAudit(t)

	t.Run("filter capped at 1 KiB", func(t *testing.T) {
		f := stSetup(t, ttOpts{})
		// ~2.5 KiB and valid under the filter policy (D6: ≤ 64 components,
		// depth ≤ 16): 41 components, depth 2.
		long := "(|" + strings.Repeat("(cn="+strings.Repeat("x", 55)+")", 40) + ")"
		f.mustSearch(t, SearchRequest{Filter: long})
		rows := f.searched(t)
		if len(rows) != 1 {
			t.Fatalf("rows = %d", len(rows))
		}
		got, _ := ttDetails(t, &rows[0])["filter"].(string)
		if got == "" || len(got) > 1024 || !strings.HasPrefix(stCanon(t, long), got) {
			t.Fatalf("details filter has %d bytes, want a non-empty prefix of the canonical filter of at most 1024", len(got))
		}
	})
}

// Search shares the per-tenant directory rate limit with connection tests.
func TestSearchRateLimit(t *testing.T) {
	f := stSetup(t, ttOpts{rate: 2})
	f.mustSearch(t, SearchRequest{})
	f.mustSearch(t, SearchRequest{})
	opens := len(f.dir.Opens())
	_, err := f.search(SearchRequest{})
	if !errors.Is(err, ErrRateLimited) || err.Error() != "rate_limited" {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if len(f.dir.Opens()) != opens {
		t.Fatal("a rate-limited search must not reach the directory")
	}
	refused := 0
	for _, r := range f.searched(t) {
		if r.Outcome == "refused" && r.Reason == "rate_limited" && r.TenantID == ttTenant {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("rate_limited directory_searched rows = %d", refused)
	}
	// Per tenant: the other tenant is not limited (its bind fails, which is
	// fine here).
	if _, err := f.svc.Search(context.Background(), ttAdmin(ttOther), ttOther, ttOtherC, SearchRequest{}); errors.Is(err, ErrRateLimited) {
		t.Fatal("other tenant rate limited")
	}

	t.Run("shared with tests", func(t *testing.T) {
		f := stSetup(t, ttOpts{rate: 1})
		if _, err := f.svc.TestSaved(context.Background(), ttAdmin(ttTenant), ttTenant, ttConnID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.search(SearchRequest{}); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("search after a test at limit 1: %v, want rate_limited", err)
		}
	})
}

func TestSearchTenantIsolation(t *testing.T) {
	f := stSetup(t, ttOpts{})
	ctx := context.Background()
	_, err := f.svc.Search(ctx, ttAdmin(ttTenant), ttTenant, ttOtherC, SearchRequest{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign connection: %v, want ErrNotFound", err)
	}
	f.noDirectoryCalls(t)
	if x := f.events(audit.CrossTenantRefused); len(x) != 1 || x[0].TenantID != ttTenant || x[0].SubjectID == nil || *x[0].SubjectID != ttOtherC {
		t.Fatalf("cross_tenant_refused rows %+v", x)
	}
	for _, id := range []string{"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", "not-a-uuid", ""} {
		if _, err := f.svc.Search(ctx, ttAdmin(ttTenant), ttTenant, id, SearchRequest{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("id %q: %v, want ErrNotFound", id, err)
		}
	}
	if x := f.events(audit.CrossTenantRefused); len(x) != 1 {
		t.Fatalf("unknown ids must not be audited as cross-tenant (rows = %d)", len(x))
	}
	f.noDirectoryCalls(t)
}

// SearchResult marshals nullable fields as null (contracts §A).
func TestSearchResultJSON(t *testing.T) {
	res := SearchResult{
		Items: []SearchItem{
			{UID: "u1", DN: "uid=a," + ttBaseDN, DisplayName: "A", Status: "new"},
			{UID: "u2", DN: "uid=b," + ttBaseDN, Email: "b@example.test", DisplayName: "B", Status: "imported", UserID: stUserImported},
			{DN: "uid=c," + ttBaseDN, Status: "invalid", Reason: "multi_valued_uid"},
		},
		Truncated: true, OutOfScope: 2, EffectiveFilter: "(&(objectClass=*)(objectClass=*))",
	}
	js, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Items           []map[string]any `json:"items"`
		Truncated       bool             `json:"truncated"`
		OutOfScope      int              `json:"out_of_scope"`
		EffectiveFilter string           `json:"effective_filter"`
	}
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.OutOfScope != 2 || got.EffectiveFilter != res.EffectiveFilter || len(got.Items) != 3 {
		t.Fatalf("json %s", js)
	}
	keys := []string{"uid", "dn", "email", "display_name", "first_name", "last_name", "status", "user_id", "reason"}
	for i, it := range got.Items {
		if len(it) != len(keys) {
			t.Fatalf("item %d keys %v, want exactly %v", i, it, keys)
		}
		for _, k := range keys {
			if _, ok := it[k]; !ok {
				t.Fatalf("item %d lacks %q", i, k)
			}
		}
	}
	if got.Items[0]["email"] != nil || got.Items[0]["user_id"] != nil || got.Items[0]["reason"] != nil {
		t.Fatalf("empty email/user_id/reason must be null: %v", got.Items[0])
	}
	if got.Items[1]["email"] != "b@example.test" || got.Items[1]["user_id"] != stUserImported {
		t.Fatalf("item 1 %v", got.Items[1])
	}
	if got.Items[2]["reason"] != "multi_valued_uid" {
		t.Fatalf("item 2 %v", got.Items[2])
	}

	empty, _ := json.Marshal(SearchResult{Items: []SearchItem{}})
	if !strings.Contains(string(empty), `"items":[]`) {
		t.Fatalf("no matches must marshal items as [], got %s", empty)
	}
}
