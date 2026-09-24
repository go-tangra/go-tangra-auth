package directory

// Tests first for import (T042, US2; research D8): every selected uid is
// re-fetched with (&<base_filter>(<uid_attr>=<escaped uid>)) under the
// connection base, so a browser cannot forge entries or inject filter syntax;
// per-entry outcomes created / updated / skipped / failed; created users are
// "imported" with no password and no MFA and carry a link row; re-import is
// idempotent (SC-004) and refreshes names/e-mail only while the user is still
// imported; one failing entry never affects the others; more than 500 uids
// are refused; import never writes an outbox row; the directory_imported
// audit event holds counts and user ids only.
//
// Helpers carry an "it" prefix so they cannot collide with the CRUD, test
// and search suites of the same package.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/config"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/ldapdir/ldapfake"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const (
	itTenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5a01"
	itOther  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5a02"
	itConnID = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5a03"
	itOtherC = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5a04"
	itActor  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5a05"

	itConnName   = "Corp LDAP"
	itBindDN     = "cn=reader,dc=example,dc=test"
	itBaseDN     = "ou=Engineering,dc=example,dc=test"
	itSiblingDN  = "ou=Sales,dc=example,dc=test"
	itURL        = "ldaps://ldap.example.test:636"
	itBindPW     = "Import-S3ntinel-Pw-4b21"
	itBaseFilter = "(objectClass=person)"

	// Directory uids (entryUUID strings, used verbatim).
	itAlice = "a1a1a1a1-0000-4000-8000-000000000001"
	itBob   = "b2b2b2b2-0000-4000-8000-000000000002"
	itCarol = "c3c3c3c3-0000-4000-8000-000000000003"
	itDave  = "d4d4d4d4-0000-4000-8000-000000000004"
	itErin  = "e5e5e5e5-0000-4000-8000-000000000005"
)

// itMapped is the attribute list the seeded connection maps (openldap kind
// with displayName as the display-name attribute).
var itMapped = []string{"entryUUID", "mail", "displayName", "givenName", "sn"}

type itFixture struct {
	svc *Service
	ms  *memstore.Store
	dir *ldapfake.Directory
	sw  *itSwitch
	aw  *audit.Writer
	now time.Time
}

// itSetup wires the service over memstore + ldapfake. Tenant itTenant owns
// connection itConnID (base filter (objectClass=person), base itBaseDN);
// tenant itOther owns itOtherC. The directory holds the base, a sibling OU
// and the reader account; people are added per test with itPerson.
func itSetup(t *testing.T) *itFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: itTenant, Slug: "acme", Status: "active", Kind: "customer"})
	ms.AddTenant(store.Tenant{ID: itOther, Slug: "other", Status: "active", Kind: "customer"})
	env, err := crypto.NewEnvelope(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Directory
	pol, err := ldapdir.NewTargetPolicy(cfg.Targets)
	if err != nil {
		t.Fatal(err)
	}
	dir := itNewDirectory()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	f := &itFixture{ms: ms, dir: dir, sw: &itSwitch{cur: dir}, aw: aw, now: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)}
	f.svc = New(Deps{
		Store: ms, Directory: f.sw, Envelope: env, Policy: pol,
		Cache: cache.New(cache.NewMemory()), Audit: aw, Config: cfg,
		Now: func() time.Time { return f.now },
	})
	for _, c := range []struct{ tid, id, name string }{{itTenant, itConnID, itConnName}, {itOther, itOtherC, "Other LDAP"}} {
		enc, err := env.Encrypt([]byte(itBindPW), []byte("ldap-bind:"+c.tid+":"+c.id))
		if err != nil {
			t.Fatal(err)
		}
		if err := ms.InsertDirectoryConnection(context.Background(), store.DirectoryConnection{
			ID: c.id, TenantID: c.tid, Name: c.name, Kind: KindOpenLDAP, URL: itURL, TLSMode: ldapdir.TLSModeLDAPS,
			BindDN: itBindDN, BindPasswordEnc: enc, BaseDN: itBaseDN, BaseFilter: itBaseFilter,
			AttrUID: "entryUUID", AttrEmail: "mail", AttrDisplayName: "displayName", AttrFirstName: "givenName", AttrLastName: "sn",
			SizeLimit: 500, TimeLimitSeconds: 15,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Import never sends mail: checked after every test.
	t.Cleanup(func() {
		if n := len(ms.Outbox); n != 0 {
			t.Errorf("import wrote %d outbox rows; it must never send e-mail", n)
		}
	})
	return f
}

// itPerson adds a person entry under parent. Empty fields are omitted.
func (f *itFixture) itPerson(parent, cn, uid, mail, given, sn, display string) string {
	dn := "cn=" + cn + "," + parent
	attrs := map[string][][]byte{"objectclass": ldapfake.Vals("person", "inetOrgPerson"), "cn": ldapfake.Vals(cn)}
	for k, v := range map[string]string{"entryUUID": uid, "mail": mail, "givenName": given, "sn": sn, "displayName": display} {
		if v != "" {
			attrs[k] = ldapfake.Vals(v)
		}
	}
	f.dir.Add(ldapfake.Entry{DN: dn, Attrs: attrs})
	return dn
}

// itSwitch lets a test replace the whole directory (the fake has no modify)
// while the service keeps the same ldapdir.Directory.
type itSwitch struct{ cur *ldapfake.Directory }

func (w *itSwitch) Open(ctx context.Context, p ldapdir.ConnParams) (ldapdir.Session, error) {
	return w.cur.Open(ctx, p)
}

// itNewDirectory returns a fake holding the base, a sibling OU and the
// reader account.
func itNewDirectory() *ldapfake.Directory {
	dir := ldapfake.New()
	dir.Add(ldapfake.Entry{DN: "dc=example,dc=test", Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("domain")}})
	dir.Add(ldapfake.Entry{DN: itBaseDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("organizationalUnit")}})
	dir.Add(ldapfake.Entry{DN: itSiblingDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("organizationalUnit")}})
	dir.Add(ldapfake.Entry{DN: itBindDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("person")}})
	dir.SetCredentials(itBindDN, itBindPW)
	return dir
}

// itReplace starts a fresh directory holding only one person, as if that
// person's entry had been edited (or moved) since the last import.
func (f *itFixture) itReplace(parent, cn, uid, mail, given, sn, display string) {
	f.dir = itNewDirectory()
	f.sw.cur = f.dir
	f.itPerson(parent, cn, uid, mail, given, sn, display)
}

func itAdmin(tid string) tenantctx.Actor {
	return tenantctx.Actor{Kind: tenantctx.KindUser, UserID: itActor, TenantID: tid, Roles: []string{"admin"}}
}

func (f *itFixture) importUIDs(t *testing.T, uids ...string) ImportResult {
	t.Helper()
	res, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, itConnID, uids)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n := f.dir.OpenSessions(); n != 0 {
		t.Fatalf("%d directory sessions left open", n)
	}
	itAccounted(t, res, uids)
	return res
}

// itAccounted checks every requested uid appears in exactly one outcome list.
func itAccounted(t *testing.T, res ImportResult, uids []string) {
	t.Helper()
	seen := map[string]int{}
	for _, it := range res.Created {
		seen[it.UID]++
	}
	for _, it := range res.Updated {
		seen[it.UID]++
	}
	for _, it := range res.Skipped {
		seen[it.UID]++
	}
	for _, it := range res.Failed {
		seen[it.UID]++
	}
	for _, u := range uids {
		if seen[u] != 1 {
			t.Fatalf("uid %q reported %d times, want exactly once: %+v", u, seen[u], res)
		}
	}
	if len(seen) != len(uids) {
		t.Fatalf("result reports uids that were not requested: %+v", res)
	}
}

func itFind(items []ImportItem, uid string) (ImportItem, bool) {
	for _, it := range items {
		if it.UID == uid {
			return it, true
		}
	}
	return ImportItem{}, false
}

func itReason(items []ImportIssue, uid string) string {
	for _, it := range items {
		if it.UID == uid {
			return it.Reason
		}
	}
	return ""
}

func (f *itFixture) user(t *testing.T, tid, id string) store.User {
	t.Helper()
	u, err := f.ms.User(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("user %s: %v", id, err)
	}
	return u
}

func (f *itFixture) link(t *testing.T, uid string) store.DirectoryLink {
	t.Helper()
	links, err := f.ms.LinksByUIDs(context.Background(), itTenant, itConnID, []string{uid})
	if err != nil {
		t.Fatal(err)
	}
	l, ok := links[uid]
	if !ok {
		t.Fatalf("no link row for uid %q", uid)
	}
	return l
}

func (f *itFixture) userCount(tid string) int {
	us, _ := f.ms.ListUsers(context.Background(), tid, "", "", 0)
	return len(us)
}

func (f *itFixture) events(typ audit.EventType) []store.AuditRow {
	f.aw.Flush()
	var out []store.AuditRow
	for i := range f.ms.AuditRows {
		if f.ms.AuditRows[i].EventType == string(typ) {
			out = append(out, f.ms.AuditRows[i])
		}
	}
	return out
}

// itSplitFilter parses a recorded filter and returns the base child and
// the (attribute, value) of the uid equality child of the root AND.
func itSplitFilter(t *testing.T, filter string) (base, attr string, value []byte) {
	t.Helper()
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("recorded filter does not compile: %v", err)
	}
	if p.Tag != ldap.FilterAnd || len(p.Children) != 2 {
		t.Fatalf("recorded filter %q is not (&base (uid=...))", filter)
	}
	base, err = ldap.DecompileFilter(p.Children[0])
	if err != nil {
		t.Fatal(err)
	}
	eq := p.Children[1]
	if eq.Tag != ldap.FilterEqualityMatch {
		t.Fatalf("second child of %q is not an equality match", filter)
	}
	return base, eq.Children[0].Data.String(), eq.Children[1].Data.Bytes()
}

// ---------------------------------------------------------------- re-fetch

func TestImportRefetchesEachUIDUnderBase(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "Alice L.")
	f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "Builder", "")

	f.importUIDs(t, itAlice, itBob)

	calls := f.dir.Searches()
	if len(calls) != 2 {
		t.Fatalf("searches = %d, want one re-fetch per uid", len(calls))
	}
	wantBase, err := ldap.CompileFilter(itBaseFilter)
	if err != nil {
		t.Fatal(err)
	}
	wantBaseStr, _ := ldap.DecompileFilter(wantBase)
	got := map[string]bool{}
	for _, c := range calls {
		q := c.Query
		if q.BaseDN != itBaseDN || q.Scope != ldapdir.ScopeSub {
			t.Fatalf("re-fetch base/scope = %q/%v, want the connection base, subtree", q.BaseDN, q.Scope)
		}
		if c.Deref != ldap.NeverDerefAliases {
			t.Fatal("re-fetch must never dereference aliases")
		}
		if q.SizeLimit < 1 || q.TimeLimit <= 0 {
			t.Fatalf("re-fetch limits = %d/%v, want bounded", q.SizeLimit, q.TimeLimit)
		}
		base, attr, val := itSplitFilter(t, q.Filter)
		if base != wantBaseStr {
			t.Fatalf("base child = %q, want %q", base, wantBaseStr)
		}
		if !strings.EqualFold(attr, "entryUUID") {
			t.Fatalf("uid attribute = %q, want entryUUID", attr)
		}
		got[string(val)] = true
		want := map[string]bool{}
		for _, a := range itMapped {
			want[strings.ToLower(a)] = true
		}
		if len(q.Attributes) != len(want) {
			t.Fatalf("attributes = %v, want exactly the mapped list %v", q.Attributes, itMapped)
		}
		for _, a := range q.Attributes {
			if !want[strings.ToLower(a)] {
				t.Fatalf("attribute %q is not mapped", a)
			}
		}
	}
	if !got[itAlice] || !got[itBob] {
		t.Fatalf("re-fetched uids = %v, want both", got)
	}
	for _, b := range f.dir.Binds() {
		if b.DN != itBindDN {
			t.Fatalf("bound as %q, want the connection bind DN", b.DN)
		}
	}
}

func TestImportInjectedUIDMatchesNothing(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "")
	f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "Builder", "")

	injected := []string{"*", "*)(mail=*", itAlice[:8] + "*", ")(objectClass=*", `\2a`, "a1a1a1a1*)(|(entryUUID=*"}
	res := f.importUIDs(t, injected...)
	if len(res.Created)+len(res.Updated) != 0 {
		t.Fatalf("an injected uid imported someone: %+v", res)
	}
	for _, u := range injected {
		if r := itReason(res.Skipped, u); r != "not_found_in_directory" {
			t.Fatalf("uid %q: reason %q, want not_found_in_directory", u, r)
		}
	}
	// The value reaches the directory as one literal assertion value.
	for _, c := range f.dir.Searches() {
		_, _, val := itSplitFilter(t, c.Query.Filter)
		found := false
		for _, u := range injected {
			if string(val) == u {
				found = true
			}
		}
		if !found {
			t.Fatalf("assertion value %q is not one of the requested uids verbatim", val)
		}
	}
	if n := f.userCount(itTenant); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

func TestImportNotFoundInDirectory(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "")
	// Outside the connection base: must not be found.
	f.itPerson(itSiblingDN, "Sam", itBob, "sam@example.test", "Sam", "Sales", "")
	// Inside the base but excluded by the base filter.
	f.dir.Add(ldapfake.Entry{DN: "cn=printer," + itBaseDN, Attrs: map[string][][]byte{
		"objectclass": ldapfake.Vals("device"), "entryuuid": ldapfake.Vals(itCarol), "mail": ldapfake.Vals("printer@example.test"),
	}})

	res := f.importUIDs(t, itAlice, itBob, itCarol, itDave)
	if _, ok := itFind(res.Created, itAlice); !ok {
		t.Fatalf("alice not created: %+v", res)
	}
	for _, u := range []string{itBob, itCarol, itDave} {
		if r := itReason(res.Skipped, u); r != "not_found_in_directory" {
			t.Fatalf("uid %s: reason %q, want not_found_in_directory", u, r)
		}
	}
	if n := f.userCount(itTenant); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}

// ---------------------------------------------------------------- created

func TestImportCreatesImportedUsers(t *testing.T) {
	f := itSetup(t)
	dn := f.itPerson(itBaseDN, "Alice", itAlice, "  Alice@Example.TEST ", "Alice", "Liddell", "Alice L.")
	f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "Builder", "")
	// Same e-mail in another tenant does not block this tenant.
	f.ms.AddUser(store.User{ID: store.NewID(), TenantID: itOther, Email: "bob@example.test", Status: "active"})

	res := f.importUIDs(t, itAlice, itBob)
	if len(res.Created) != 2 || len(res.Updated)+len(res.Skipped)+len(res.Failed) != 0 {
		t.Fatalf("result = %+v, want two created", res)
	}
	ca, _ := itFind(res.Created, itAlice)
	u := f.user(t, itTenant, ca.UserID)
	if u.Status != "imported" {
		t.Fatalf("status = %q, want imported", u.Status)
	}
	if u.PasswordHash != nil || u.PasswordChangedAt != nil {
		t.Fatal("an imported user must have no password")
	}
	if u.MFAEnabled || len(u.MFASecretEnc) != 0 {
		t.Fatal("an imported user must have no MFA")
	}
	if u.LastSigninAt != nil {
		t.Fatal("an imported user has never signed in")
	}
	if u.Email != "alice@example.test" {
		t.Fatalf("email = %q, want normalised like invitations", u.Email)
	}
	if u.FirstName != "Alice" || u.LastName != "Liddell" || u.DisplayName != "Alice L." || !u.DisplayNameExplicit {
		t.Fatalf("names = %q/%q/%q explicit=%v", u.FirstName, u.LastName, u.DisplayName, u.DisplayNameExplicit)
	}

	l := f.link(t, itAlice)
	if l.UserID != ca.UserID || l.TenantID != itTenant {
		t.Fatalf("link user/tenant = %s/%s", l.UserID, l.TenantID)
	}
	if l.ConnectionID == nil || *l.ConnectionID != itConnID || l.ConnectionName != itConnName {
		t.Fatalf("link connection = %v/%q", l.ConnectionID, l.ConnectionName)
	}
	if l.DirectoryUID != itAlice || l.DirectoryDN != dn {
		t.Fatalf("link uid/dn = %q/%q", l.DirectoryUID, l.DirectoryDN)
	}
	if !l.FirstImportedAt.Equal(f.now) || !l.LastImportedAt.Equal(f.now) {
		t.Fatalf("link timestamps = %v/%v, want %v", l.FirstImportedAt, l.LastImportedAt, f.now)
	}
	if l.ImportedBy == nil || *l.ImportedBy != itActor {
		t.Fatalf("imported_by = %v, want the actor", l.ImportedBy)
	}

	// No display-name attribute: derived, not explicit.
	cb, _ := itFind(res.Created, itBob)
	b := f.user(t, itTenant, cb.UserID)
	if b.DisplayNameExplicit || b.DisplayName == "" {
		t.Fatalf("bob display name = %q explicit=%v, want a derived name", b.DisplayName, b.DisplayNameExplicit)
	}
	if b.TenantID != itTenant {
		t.Fatal("user created in the wrong tenant")
	}
}

// ---------------------------------------------------------------- skipped

func TestImportSkipReasons(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "NoMail", itAlice, "", "No", "Mail", "")
	f.itPerson(itBaseDN, "BadMail", itBob, "not-an-email", "Bad", "Mail", "")
	f.itPerson(itBaseDN, "Long", itCarol, "long@example.test", strings.Repeat("x", 101), "Name", "")

	res := f.importUIDs(t, itAlice, itBob, itCarol)
	want := map[string]string{itAlice: "no_email", itBob: "invalid_email", itCarol: "value_too_long"}
	for uid, reason := range want {
		if r := itReason(res.Skipped, uid); r != reason {
			t.Fatalf("uid %s: reason %q, want %q", uid, r, reason)
		}
	}
	if n := f.userCount(itTenant); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
	// Wire form: empty lists are [] and every skip has a uid and a reason.
	js, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(js, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"created", "updated", "failed"} {
		if string(wire[k]) != "[]" {
			t.Fatalf("%s = %s, want []", k, wire[k])
		}
	}
	if !strings.Contains(string(wire["skipped"]), `"uid":"`+itAlice+`","reason":"no_email"`) {
		t.Fatalf("skipped wire form = %s", wire["skipped"])
	}
}

func TestImportEmailInUse(t *testing.T) {
	for _, status := range []string{"active", "invited", "deactivated", "imported"} {
		t.Run(status, func(t *testing.T) {
			f := itSetup(t)
			f.ms.AddUser(store.User{ID: store.NewID(), TenantID: itTenant, Email: "alice@example.test", Status: status, DisplayName: "Existing"})
			f.itPerson(itBaseDN, "Alice", itAlice, "ALICE@example.test", "Alice", "Liddell", "")

			res := f.importUIDs(t, itAlice)
			if r := itReason(res.Skipped, itAlice); r != "email_in_use" {
				t.Fatalf("reason %q, want email_in_use", r)
			}
			if n := f.userCount(itTenant); n != 1 {
				t.Fatalf("users = %d, want the existing one only", n)
			}
			links, _ := f.ms.LinksByUIDs(context.Background(), itTenant, itConnID, []string{itAlice})
			if len(links) != 0 {
				t.Fatal("a skipped entry must not be linked")
			}
		})
	}
}

func TestImportDuplicateEmailInRequest(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "shared@example.test", "Alice", "One", "")
	f.itPerson(itBaseDN, "Alice2", itBob, "Shared@Example.test", "Alice", "Two", "")

	res := f.importUIDs(t, itAlice, itBob)
	if _, ok := itFind(res.Created, itAlice); !ok {
		t.Fatalf("first entry not created: %+v", res)
	}
	if r := itReason(res.Skipped, itBob); r != "duplicate_email" {
		t.Fatalf("second entry reason %q, want duplicate_email", r)
	}
	if n := f.userCount(itTenant); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}

func TestImportAlreadyActiveKeepsPlatformProfile(t *testing.T) {
	for _, status := range []string{"invited", "active", "deactivated"} {
		t.Run(status, func(t *testing.T) {
			f := itSetup(t)
			f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "Alice L.")
			first := f.importUIDs(t, itAlice)
			id := first.Created[0].UserID
			if err := f.ms.UpdateUserStatus(context.Background(), itTenant, id, status); err != nil {
				t.Fatal(err)
			}
			before := f.user(t, itTenant, id)

			f.itReplace(itBaseDN, "Alice", itAlice, "alice.new@example.test", "Alicia", "Smith", "Alicia S.")
			f.now = f.now.Add(time.Hour)
			res := f.importUIDs(t, itAlice)
			if r := itReason(res.Skipped, itAlice); r != "already_active" {
				t.Fatalf("reason %q, want already_active", r)
			}
			after := f.user(t, itTenant, id)
			if after.Email != before.Email || after.FirstName != before.FirstName || after.LastName != before.LastName ||
				after.DisplayName != before.DisplayName || after.Status != status {
				t.Fatalf("platform profile changed after activation: %+v → %+v", before, after)
			}
		})
	}
}

// ---------------------------------------------------------------- updated / idempotency

func TestImportIdempotent(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "")
	f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "Builder", "")

	first := f.importUIDs(t, itAlice, itBob)
	if len(first.Created) != 2 {
		t.Fatalf("first run = %+v", first)
	}
	firstLink := f.link(t, itAlice)
	f.now = f.now.Add(2 * time.Hour)

	second := f.importUIDs(t, itAlice, itBob)
	if len(second.Created) != 0 || len(second.Updated) != 2 || len(second.Skipped)+len(second.Failed) != 0 {
		t.Fatalf("second run = %+v, want two updated and nothing created", second)
	}
	for _, c := range first.Created {
		u, ok := itFind(second.Updated, c.UID)
		if !ok || u.UserID != c.UserID {
			t.Fatalf("uid %s re-import user id = %q, want %q", c.UID, u.UserID, c.UserID)
		}
		if st := f.user(t, itTenant, c.UserID).Status; st != "imported" {
			t.Fatalf("status after re-import = %q", st)
		}
	}
	if n := f.userCount(itTenant); n != 2 {
		t.Fatalf("users = %d after re-import, want 2 (SC-004)", n)
	}
	l := f.link(t, itAlice)
	if !l.FirstImportedAt.Equal(firstLink.FirstImportedAt) || !l.LastImportedAt.Equal(f.now) {
		t.Fatalf("link times = %v/%v, want first kept and last = %v", l.FirstImportedAt, l.LastImportedAt, f.now)
	}
}

func TestImportRefreshesImportedProfile(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "Alice L.")
	id := f.importUIDs(t, itAlice).Created[0].UserID

	f.itReplace(itBaseDN, "Alicia", itAlice, "alicia@example.test", "Alicia", "Smith", "Alicia S.")
	res := f.importUIDs(t, itAlice)
	if u, ok := itFind(res.Updated, itAlice); !ok || u.UserID != id {
		t.Fatalf("result = %+v, want updated with the same user id", res)
	}
	u := f.user(t, itTenant, id)
	if u.Email != "alicia@example.test" || u.FirstName != "Alicia" || u.LastName != "Smith" || u.DisplayName != "Alicia S." {
		t.Fatalf("profile not refreshed: %+v", u)
	}
	if u.Status != "imported" {
		t.Fatalf("status = %q", u.Status)
	}
	if l := f.link(t, itAlice); l.DirectoryDN != "cn=Alicia,"+itBaseDN {
		t.Fatalf("link dn = %q, want the last seen DN", l.DirectoryDN)
	}
}

func TestImportRefreshKeepsEmailTakenByAnotherUser(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "")
	id := f.importUIDs(t, itAlice).Created[0].UserID
	f.ms.AddUser(store.User{ID: store.NewID(), TenantID: itTenant, Email: "taken@example.test", Status: "active"})

	f.itReplace(itBaseDN, "Alice", itAlice, "taken@example.test", "Alicia", "Smith", "")
	res := f.importUIDs(t, itAlice)
	if _, ok := itFind(res.Updated, itAlice); !ok {
		t.Fatalf("result = %+v, want updated (names refreshed, e-mail kept)", res)
	}
	u := f.user(t, itTenant, id)
	if u.Email != "alice@example.test" {
		t.Fatalf("email = %q, want the old one kept", u.Email)
	}
	if u.FirstName != "Alicia" || u.LastName != "Smith" {
		t.Fatalf("names not refreshed: %q %q", u.FirstName, u.LastName)
	}
}

// ---------------------------------------------------------------- failures

func TestImportPerEntryFailureIsolation(t *testing.T) {
	t.Run("store", func(t *testing.T) {
		f := itSetup(t)
		f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")
		f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "B", "")
		f.itPerson(itBaseDN, "Carol", itCarol, "carol@example.test", "Carol", "C", "")
		f.ms.FailNext("UpsertLink")

		res := f.importUIDs(t, itAlice, itBob, itCarol)
		if len(res.Failed) != 1 || res.Failed[0].Reason != "internal" {
			t.Fatalf("failed = %+v, want exactly one internal", res.Failed)
		}
		if len(res.Created) != 2 {
			t.Fatalf("created = %+v, want the other two", res.Created)
		}
		for _, c := range res.Created {
			f.link(t, c.UID)
		}
	})
	t.Run("directory", func(t *testing.T) {
		f := itSetup(t)
		f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")
		f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "B", "")
		f.itPerson(itBaseDN, "Carol", itCarol, "carol@example.test", "Carol", "C", "")
		f.dir.InjectError(ldapfake.OpSearch, nil, &ldapdir.DirectoryError{Code: 80}, nil)

		res := f.importUIDs(t, itAlice, itBob, itCarol)
		if r := itReason(res.Failed, itBob); r != "directory_error" {
			t.Fatalf("second entry reason %q, want directory_error (result %+v)", r, res)
		}
		if len(res.Created) != 2 {
			t.Fatalf("created = %+v, want the other two", res.Created)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := itSetup(t)
		f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")
		f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "B", "")
		f.dir.InjectError(ldapfake.OpSearch, ldapdir.ErrTimeout)

		res := f.importUIDs(t, itAlice, itBob)
		if r := itReason(res.Failed, itAlice); r != "timeout" {
			t.Fatalf("reason %q, want timeout (result %+v)", r, res)
		}
		for _, x := range res.Failed {
			switch x.Reason {
			case "directory_error", "timeout", "internal":
			default:
				t.Fatalf("failed reason %q outside the closed vocabulary", x.Reason)
			}
		}
	})
}

func TestImportDirectoryUnavailable(t *testing.T) {
	cases := []struct {
		name string
		op   ldapfake.Op
		err  error
	}{
		{"open", ldapfake.OpOpen, ldapdir.ErrUnreachable},
		{"tls", ldapfake.OpOpen, ldapdir.ErrTLS},
		{"bind", ldapfake.OpBind, ldapdir.ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := itSetup(t)
			f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")
			f.dir.InjectError(tc.op, tc.err)
			_, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, itConnID, []string{itAlice})
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if n := f.userCount(itTenant); n != 0 {
				t.Fatalf("users = %d, want nothing imported", n)
			}
			if n := f.dir.OpenSessions(); n != 0 {
				t.Fatalf("%d sessions left open", n)
			}
			if strings.Contains(err.Error(), itBindPW) {
				t.Fatal("error leaks the bind password")
			}
		})
	}
}

// ---------------------------------------------------------------- request bounds and tenancy

func TestImportRequestBounds(t *testing.T) {
	f := itSetup(t)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		}
		return out
	}
	for name, uids := range map[string][]string{
		"none":      nil,
		"empty":     {},
		"501":       many(501),
		"duplicate": {itAlice, itBob, itAlice},
		"blank":     {itAlice, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, itConnID, uids)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
			if n := len(f.dir.Opens()); n != 0 {
				t.Fatalf("directory opened %d times for a refused request", n)
			}
		})
	}
	t.Run("500 accepted", func(t *testing.T) {
		res, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, itConnID, many(500))
		if err != nil {
			t.Fatalf("500 uids refused: %v", err)
		}
		if len(res.Skipped) != 500 {
			t.Fatalf("skipped = %d, want 500 not_found_in_directory", len(res.Skipped))
		}
	})
}

func TestImportConnectionTenancy(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")

	_, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, itOtherC, []string{itAlice})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign connection: err = %v, want ErrNotFound", err)
	}
	if rows := f.events(audit.CrossTenantRefused); len(rows) != 1 || rows[0].SubjectID == nil || *rows[0].SubjectID != itOtherC {
		t.Fatalf("cross_tenant_refused rows = %d, want one for the foreign id", len(rows))
	}
	for _, id := range []string{"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b5aff", "not-a-uuid"} {
		if _, err := f.svc.Import(context.Background(), itAdmin(itTenant), itTenant, id, []string{itAlice}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown connection %q: err = %v, want ErrNotFound", id, err)
		}
	}
	if n := len(f.dir.Opens()); n != 0 {
		t.Fatalf("directory opened %d times without a connection", n)
	}
	if n := f.userCount(itTenant) + f.userCount(itOther); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

// ---------------------------------------------------------------- audit

func TestImportAudit(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "Liddell", "Alice L.")
	f.itPerson(itBaseDN, "Bob", itBob, "bob@example.test", "Bob", "Builder", "")
	f.itPerson(itBaseDN, "NoMail", itCarol, "", "Nora", "Mailless", "")
	first := f.importUIDs(t, itAlice)
	f.dir.InjectError(ldapfake.OpSearch, nil, nil, nil, &ldapdir.DirectoryError{Code: 80})

	res := f.importUIDs(t, itAlice, itBob, itCarol, itErin)
	if len(res.Updated) != 1 || len(res.Created) != 1 || len(res.Skipped) != 1 || len(res.Failed) != 1 {
		t.Fatalf("result = %+v, want 1 of each outcome", res)
	}

	rows := f.events(audit.DirectoryImported)
	if len(rows) != 2 {
		t.Fatalf("directory_imported rows = %d, want one per import call", len(rows))
	}
	r := rows[1]
	if r.TenantID != itTenant || r.Outcome != "ok" || r.ActorUserID == nil || *r.ActorUserID != itActor {
		t.Fatalf("audit row tenant/outcome/actor = %s/%s/%v", r.TenantID, r.Outcome, r.ActorUserID)
	}
	if r.SubjectKind != subjectKind || r.SubjectID == nil || *r.SubjectID != itConnID {
		t.Fatalf("audit subject = %s/%v, want the connection", r.SubjectKind, r.SubjectID)
	}
	var d struct {
		Created        *int     `json:"created"`
		Updated        *int     `json:"updated"`
		Skipped        *int     `json:"skipped"`
		Failed         *int     `json:"failed"`
		CreatedUserIDs []string `json:"created_user_ids"`
		UpdatedUserIDs []string `json:"updated_user_ids"`
	}
	if err := json.Unmarshal(r.Details, &d); err != nil {
		t.Fatal(err)
	}
	if d.Created == nil || d.Updated == nil || d.Skipped == nil || d.Failed == nil ||
		*d.Created != 1 || *d.Updated != 1 || *d.Skipped != 1 || *d.Failed != 1 {
		t.Fatalf("audit counts = %s, want 1/1/1/1", r.Details)
	}
	if len(d.CreatedUserIDs) != 1 || d.CreatedUserIDs[0] != res.Created[0].UserID {
		t.Fatalf("created_user_ids = %v, want %s", d.CreatedUserIDs, res.Created[0].UserID)
	}
	if len(d.UpdatedUserIDs) != 1 || d.UpdatedUserIDs[0] != first.Created[0].UserID {
		t.Fatalf("updated_user_ids = %v", d.UpdatedUserIDs)
	}

	// Ids and counts only: no e-mails, names, DNs, directory uids or secrets.
	details := string(r.Details)
	for _, s := range []string{"@example.test", "Alice", "Liddell", "Builder", "Nora", "dc=example", "cn=", itAlice, itBob, itCarol, itErin, itBindPW} {
		if strings.Contains(details, s) {
			t.Fatalf("directory_imported details contain %q: %s", s, details)
		}
	}
	allowed := map[string]bool{itConnID: true, res.Created[0].UserID: true, first.Created[0].UserID: true}
	for _, reason := range []string{"no_email", "invalid_email", "email_in_use", "duplicate_email", "already_active",
		"not_found_in_directory", "value_too_long", "directory_error", "timeout", "internal"} {
		allowed[reason] = true // closed vocabulary (e.g. per-reason counts) is not PII
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if !allowed[x] {
				t.Fatalf("directory_imported details carry the string %q; only ids are allowed", x)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var generic any
	_ = json.Unmarshal(r.Details, &generic)
	walk(generic)
}
