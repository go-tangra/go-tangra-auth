package directory

// Redaction sentinel scan (T063; SR-002, SC-006; research D4/D9): drives
// every directory operation — create, update, test, search, import and
// remove — with the LDAP-MARKER sentinel bind password and asserts it never
// reaches a response (the JSON views and results the HTTP layer writes
// verbatim as response bodies), an error string, an audit row or the
// captured output: this file never prints a checked string, and every
// observation is also written via capture() for scripts/redaction-scan.sh,
// which greps the capture directory and the verbose suite log for
// LDAP-MARKER-PW-*.
//
// The connection-test flow is driven against a wrapped directory that echoes
// the presented bind password in its failure diagnostics, as a verbose or
// hostile server would after seeing it: the flow reduces every failure to a
// closed reason, so the echo text must never survive it. Search and import
// trust the ldapdir client boundary, which drops the server's diagnostic
// text before the service sees it (research D4/D9, verified against a
// scripted echoing server in the ldapdir client tests), so those flows are
// driven with the closed errors the client produces — a bare sentinel or a
// *ldapdir.DirectoryError code, never text.
//
// Helpers carry an "rs" prefix so they cannot collide with the crud/tt/st/it
// suites of this package.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/config"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/ldapdir/ldapfake"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
)

const (
	rsTenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1c7a01"
	rsOther  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1c7a02"
	rsConnID = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1c7a03"
	rsOtherC = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1c7a04"

	rsBindDN = "cn=reader,dc=example,dc=test"
	rsBaseDN = "ou=People,dc=example,dc=test"
	rsURL    = "ldaps://ldap.example.test:636"

	// The redaction-scan sentinel (scripts/redaction-scan.sh greps captured
	// output for LDAP-MARKER-PW-*): none of these may ever reach a sink.
	rsPW  = "LDAP-MARKER-PW-redact1"
	rsPW2 = "LDAP-MARKER-PW-redact2"
	rsPW3 = "LDAP-MARKER-PW-redact3"
)

var rsSecrets = []string{rsPW, rsPW2, rsPW3, "LDAP-MARKER-PW-"}

type rsFixture struct {
	svc *Service
	ms  *memstore.Store
	dir *ldapfake.Directory
	aw  *audit.Writer
	env *crypto.Envelope
}

// rsSetup wires the service over memstore + ldapfake. The directory honours
// the reader account with rsPW; tenant rsTenant owns rsConnID (sealed rsPW),
// tenant rsOther owns rsOtherC (sealed rsPW2). With echo true the directory
// is wrapped so failures carry the bind password in their diagnostic text
// (rsEchoDir).
func rsSetup(t *testing.T, echo bool) *rsFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: rsTenant, Slug: "acme", Status: "active", Kind: "customer"})
	ms.AddTenant(store.Tenant{ID: rsOther, Slug: "other", Status: "active", Kind: "customer"})
	env, err := crypto.NewEnvelope(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Directory
	pol, err := ldapdir.NewTargetPolicy(cfg.Targets)
	if err != nil {
		t.Fatal(err)
	}
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	dir := ldapfake.New()
	dir.Add(ldapfake.Entry{DN: "dc=example,dc=test", Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("domain")}})
	dir.Add(ldapfake.Entry{DN: rsBaseDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("organizationalUnit")}})
	dir.Add(ldapfake.Entry{DN: rsBindDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("person")}})
	dir.SetCredentials(rsBindDN, rsPW)
	var d ldapdir.Directory = dir
	if echo {
		d = rsEchoDir{d: dir}
	}
	svc := New(Deps{
		Store: ms, Directory: d, Envelope: env, Policy: pol,
		Cache: cache.New(cache.NewMemory()), Audit: aw, Config: cfg,
	})
	f := &rsFixture{svc: svc, ms: ms, dir: dir, aw: aw, env: env}
	for _, c := range []struct{ tid, id, name, pw string }{{rsTenant, rsConnID, "Corp LDAP", rsPW}, {rsOther, rsOtherC, "Other LDAP", rsPW2}} {
		enc, err := env.Encrypt([]byte(c.pw), []byte("ldap-bind:"+c.tid+":"+c.id))
		if err != nil {
			t.Fatal(err)
		}
		if err := ms.InsertDirectoryConnection(context.Background(), store.DirectoryConnection{
			ID: c.id, TenantID: c.tid, Name: c.name, Kind: KindOpenLDAP, URL: rsURL, TLSMode: ldapdir.TLSModeLDAPS,
			BindDN: rsBindDN, BindPasswordEnc: enc, BaseDN: rsBaseDN,
			AttrUID: "entryUUID", AttrEmail: "mail", AttrDisplayName: "displayName", AttrFirstName: "givenName", AttrLastName: "sn",
			SizeLimit: 500, TimeLimitSeconds: 15,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// rsEchoDir decorates the fake directory so a failing session operation
// carries the bind password in its diagnostic text, modelling a directory
// that echoes the password it saw — the worst case for SR-002. The
// connection-test flow reduces every failure to a closed reason, so the
// echo text must never survive it; Search failures keep the fake's (closed)
// errors, standing in for the real client after it dropped server text.
type rsEchoDir struct{ d *ldapfake.Directory }

func (w rsEchoDir) Open(ctx context.Context, p ldapdir.ConnParams) (ldapdir.Session, error) {
	s, err := w.d.Open(ctx, p)
	if err != nil {
		// Open carries no password; the diagnostic stands for a server that
		// repeats what it learned from an earlier bind.
		return nil, fmt.Errorf("%w (diagnostic: refusing connections, remembered password %s)", err, rsPW)
	}
	return rsEchoSession{Session: s}, nil
}

type rsEchoSession struct{ ldapdir.Session }

func (s rsEchoSession) Bind(ctx context.Context, dn string, pw []byte) error {
	err := s.Session.Bind(ctx, dn, pw)
	if err != nil {
		return fmt.Errorf("%w (diagnostic: simple bind as %s failed, password used: %s)", err, dn, string(pw))
	}
	return nil
}

func (s rsEchoSession) BaseExists(ctx context.Context, base string) error {
	err := s.Session.BaseExists(ctx, base)
	if err != nil {
		return fmt.Errorf("%w (diagnostic: base %s unreadable, bind password %s rejected)", err, base, rsPW)
	}
	return nil
}

// rsNoSecret fails when any form of v contains a sentinel or one of the
// sealed-ciphertext encodings. It never prints v (the redaction scan greps
// the suite log).
func rsNoSecret(t *testing.T, what string, v any, cts ...[]byte) {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s does not marshal: %v", what, err)
	}
	for _, form := range []string{fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), string(js)} {
		rsNoSecretStr(t, what, form, cts...)
	}
}

// rsNoSecretStr checks one string form. The encodings matter: a sealed
// password that reached a sink in any encoding is a leak.
func rsNoSecretStr(t *testing.T, what, s string, cts ...[]byte) {
	t.Helper()
	for _, pw := range rsSecrets {
		if strings.Contains(s, pw) {
			t.Errorf("%s contains the bind password", what)
		}
	}
	for _, ct := range cts {
		if len(ct) == 0 {
			continue
		}
		for _, enc := range []string{string(ct), base64.StdEncoding.EncodeToString(ct), base64.RawURLEncoding.EncodeToString(ct), hex.EncodeToString(ct)} {
			if strings.Contains(s, enc) {
				t.Errorf("%s contains the sealed bind password", what)
			}
		}
	}
}

// rsNoSecretErr sweeps an error's string forms. Directory errors are
// additionally asserted to keep the closed reason the HTTP error body is
// built from ({reason: <closed>}); anything else would be server text.
func rsNoSecretErr(t *testing.T, what string, err error, cts ...[]byte) {
	t.Helper()
	if err == nil {
		return
	}
	rsNoSecretStr(t, what+" (error)", err.Error(), cts...)
	rsNoSecretStr(t, what+" (%+v)", fmt.Sprintf("%+v", err), cts...)
}

var rsClosedReasons = map[string]bool{
	"unreachable": true, "timeout": true, "tls_failed": true, "invalid_credentials": true,
	"base_not_found": true, "directory_error": true, "target_refused": true,
	"invalid_filter": true, "invalid_base": true,
}

// rsNoSecretReason asserts the closed projection of a directory error: the
// reason names the HTTP error body ({"reason": ...}) and the audit row, so
// it must be in the closed vocabulary and carry no sentinel.
func rsNoSecretReason(t *testing.T, what string, err error, cts ...[]byte) {
	t.Helper()
	rsNoSecretErr(t, what, err, cts...)
	r := ldapdir.Reason(err)
	if !rsClosedReasons[r] {
		t.Errorf("%s: reason %q is outside the closed vocabulary", what, r)
	}
	rsNoSecretStr(t, what+" (reason body)", `{"reason":"`+r+`"}`, cts...)
}

// rsBody marshals v the way the HTTP layer answers (WriteJSON writes the
// value verbatim) and captures both forms for the scan.
func rsBody(t *testing.T, v any) string {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	capture(t, v)
	capture(t, string(js))
	return string(js)
}

// rsAudit sweeps and captures every audit row written so far and returns a
// copy for shape assertions.
func (f *rsFixture) rsAudit(t *testing.T, cts ...[]byte) []store.AuditRow {
	t.Helper()
	f.aw.Flush()
	rows := append([]store.AuditRow(nil), f.ms.AuditRows...)
	for i := range rows {
		rsNoSecret(t, "audit row "+rows[i].EventType, rows[i], cts...)
		capture(t, rows[i])
	}
	return rows
}

// rsCiphertexts returns the sealed passwords of the seeded connections, in
// every form a leak could take.
func (f *rsFixture) rsCiphertexts(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, id := range []string{rsConnID, rsOtherC} {
		c, err := f.ms.GetDirectoryConnectionAnyTenant(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c.BindPasswordEnc)
	}
	return out
}

func (f *rsFixture) rsCiphertext(t *testing.T, tid, id string) []byte {
	t.Helper()
	c, err := f.ms.GetDirectoryConnection(context.Background(), tid, id)
	if err != nil {
		t.Fatal(err)
	}
	return c.BindPasswordEnc
}

// rsPerson adds an inetOrgPerson-like entry under the connection base with
// the seeded mapping's attributes.
func (f *rsFixture) rsPerson(cn, uid, mail string) {
	f.dir.Add(ldapfake.Entry{DN: "cn=" + cn + "," + rsBaseDN, Attrs: map[string][][]byte{
		"objectclass": ldapfake.Vals("person", "inetOrgPerson"), "cn": ldapfake.Vals(cn),
		"entryuuid": ldapfake.Vals(uid), "mail": ldapfake.Vals(mail),
		"givenname": ldapfake.Vals(cn), "sn": ldapfake.Vals("Example"), "displayname": ldapfake.Vals(cn + " Example"),
	}})
}

func (f *rsFixture) rsBound(t *testing.T, want int) {
	t.Helper()
	if f.dir.OpenSessions() != 0 {
		t.Fatal("directory session left open")
	}
	if b := f.dir.Binds(); len(b) != want {
		t.Fatalf("binds = %d, want %d", len(b), want)
	}
}

// TestRedactionCRUD drives create, update, get, list, a cross-tenant lookup
// and remove with the sentinel bind password; every response body, error
// string and audit row must stay sentinel-free.
func TestRedactionCRUD(t *testing.T) {
	f := rsSetup(t, false)
	ctx := context.Background()
	a := actorOf(rsTenant)
	cts := f.rsCiphertexts(t)

	in := Input{
		Name: sp("Fresh LDAP"), Kind: sp(KindOpenLDAP), URL: sp(rsURL), TLSMode: sp(ldapdir.TLSModeLDAPS),
		BindDN: sp(rsBindDN), BindPassword: sp(rsPW), BaseDN: sp(rsBaseDN),
	}
	v, err := f.svc.Create(ctx, a, rsTenant, in)
	if err != nil {
		t.Fatal(err)
	}
	if !v.BindPasswordSet {
		t.Fatal("bind_password_set must be true")
	}
	rsNoSecret(t, "create view", v, cts...)
	rsBody(t, v)
	created := f.rsCiphertext(t, rsTenant, v.ID)
	if len(created) == 0 || bytes.Contains(created, []byte(rsPW)) {
		t.Fatal("the password must be stored sealed")
	}
	cts = append(cts, created)

	up, err := f.svc.Update(ctx, a, rsTenant, v.ID, Input{Name: sp("Corp LDAP (rotated)"), BindPassword: sp(rsPW2)})
	if err != nil {
		t.Fatal(err)
	}
	rsNoSecret(t, "update view", up, cts...)
	rsBody(t, up)
	cts = append(cts, f.rsCiphertext(t, rsTenant, v.ID))

	got, err := f.svc.Get(ctx, a, rsTenant, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	rsNoSecret(t, "get view", got, cts...)
	rsBody(t, got)
	list, err := f.svc.List(ctx, a, rsTenant)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	rsNoSecret(t, "list view", list, cts...)
	rsBody(t, list)

	// A foreign id is not found and audited as cross_tenant_refused; the
	// target tenant detail must not carry the other tenant's password.
	if _, err := f.svc.Get(ctx, a, rsTenant, rsOtherC); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	rsNoSecretErr(t, "cross-tenant get", err, cts...)
	capture(t, err)

	if err := f.svc.Remove(ctx, a, rsTenant, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, a, rsTenant, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed connection still readable: %v", err)
	}
	rsNoSecretErr(t, "removed get", err, cts...)
	capture(t, err)

	rows := f.rsAudit(t, cts...)
	var createdRow, updatedRow, deletedRow, crossRow bool
	for i := range rows {
		r := &rows[i]
		switch r.EventType {
		case string(audit.DirectoryConnectionCreated):
			createdRow = true
		case string(audit.DirectoryConnectionUpdated):
			updatedRow = true
			d := map[string]any{}
			if err := json.Unmarshal(r.Details, &d); err != nil {
				t.Fatal(err)
			}
			fields, ok := d["fields"].([]any)
			if !ok {
				t.Fatalf("update details %v", d)
			}
			var named bool
			for _, x := range fields {
				if x == "bind_credential" {
					named = true
				}
			}
			if !named {
				t.Errorf("a password change must be audited as the field name bind_credential only, got %v", fields)
			}
		case string(audit.DirectoryConnectionDeleted):
			deletedRow = true
		case string(audit.CrossTenantRefused):
			crossRow = true
			d := map[string]any{}
			if err := json.Unmarshal(r.Details, &d); err != nil {
				t.Fatal(err)
			}
			if d["target_tenant"] != rsOther {
				t.Errorf("cross_tenant_refused details %v", d)
			}
		}
	}
	if !createdRow || !updatedRow || !deletedRow || !crossRow {
		t.Errorf("missing audit rows: created=%v updated=%v deleted=%v cross=%v", createdRow, updatedRow, deletedRow, crossRow)
	}
}

// TestRedactionConnectionTest drives the saved and typed connection tests
// against the echoing directory. The typed wrong password, a rotated
// directory password, an unreadable base and an unreachable directory all
// fail with echo text in the underlying diagnostic; the result, last_test
// and the audit rows must carry only closed reasons.
func TestRedactionConnectionTest(t *testing.T) {
	t.Run("saved ok", func(t *testing.T) {
		f := rsSetup(t, true)
		cts := f.rsCiphertexts(t)
		res, err := f.svc.TestSaved(context.Background(), actorOf(rsTenant), rsTenant, rsConnID)
		if err != nil || !res.OK {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		rsNoSecret(t, "ok result", res, cts...)
		rsBody(t, res)
		f.rsBound(t, 1)
		b := f.dir.Binds()
		if b[0].Password != rsPW {
			t.Fatal("the stored sentinel was not used for the bind")
		}
		if c := f.connOutcome(t); c != "ok" {
			t.Fatalf("last_test outcome %q", c)
		}
		f.rsAudit(t, cts...)
	})

	t.Run("typed password echoed", func(t *testing.T) {
		f := rsSetup(t, true)
		cts := f.rsCiphertexts(t)
		in := Input{
			Name: sp("Draft"), Kind: sp(KindOpenLDAP), URL: sp(rsURL), TLSMode: sp(ldapdir.TLSModeLDAPS),
			BindDN: sp(rsBindDN), BindPassword: sp(rsPW3), BaseDN: sp(rsBaseDN),
		}
		res, err := f.svc.Test(context.Background(), actorOf(rsTenant), rsTenant, in, "")
		if err != nil {
			t.Fatalf("a failing step is a result, not an error: %v", err)
		}
		if res.OK || res.Step != StepBind || res.Reason != "invalid_credentials" {
			t.Fatalf("got ok=%v step=%q reason=%q", res.OK, res.Step, res.Reason)
		}
		rsNoSecret(t, "typed-password result", res, cts...)
		rsBody(t, res)
		f.rsBound(t, 1)
		if f.dir.Binds()[0].Password != rsPW3 {
			t.Fatal("the typed sentinel was not used for the bind")
		}
		f.rsAudit(t, cts...)
	})

	t.Run("stored password echoed after rotation", func(t *testing.T) {
		f := rsSetup(t, true)
		cts := f.rsCiphertexts(t)
		f.dir.SetCredentials(rsBindDN, "rotated-in-directory")
		res, err := f.svc.TestSaved(context.Background(), actorOf(rsTenant), rsTenant, rsConnID)
		if err != nil || res.OK || res.Step != StepBind || res.Reason != "invalid_credentials" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		rsNoSecret(t, "rotated result", res, cts...)
		rsBody(t, res)
		if c := f.connOutcome(t); c != "invalid_credentials" {
			t.Fatalf("last_test outcome %q", c)
		}
		f.rsAudit(t, cts...)
	})

	t.Run("base check echoed", func(t *testing.T) {
		f := rsSetup(t, true)
		cts := f.rsCiphertexts(t)
		in := Input{
			Name: sp("Draft"), Kind: sp(KindOpenLDAP), URL: sp(rsURL), TLSMode: sp(ldapdir.TLSModeLDAPS),
			BindDN: sp(rsBindDN), BindPassword: sp(rsPW), BaseDN: sp("ou=Nope,dc=example,dc=test"),
		}
		res, err := f.svc.Test(context.Background(), actorOf(rsTenant), rsTenant, in, "")
		if err != nil || res.OK || res.Step != StepSearchBase || res.Reason != "base_not_found" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		rsNoSecret(t, "base-check result", res, cts...)
		rsBody(t, res)
		f.rsAudit(t, cts...)
	})

	t.Run("open failure echoed", func(t *testing.T) {
		f := rsSetup(t, true)
		cts := f.rsCiphertexts(t)
		f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrUnreachable)
		res, err := f.svc.TestSaved(context.Background(), actorOf(rsTenant), rsTenant, rsConnID)
		if err != nil || res.OK || res.Step != StepConnect || res.Reason != "unreachable" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		rsNoSecret(t, "open-failure result", res, cts...)
		rsBody(t, res)
		if f.dir.OpenSessions() != 0 {
			t.Fatal("directory session left open")
		}
		f.rsAudit(t, cts...)
	})
}

func (f *rsFixture) connOutcome(t *testing.T) string {
	t.Helper()
	c, err := f.ms.GetDirectoryConnection(context.Background(), rsTenant, rsConnID)
	if err != nil {
		t.Fatal(err)
	}
	if c.LastTestOutcome == nil {
		t.Fatal("last_test not persisted")
	}
	return *c.LastTestOutcome
}

// TestRedactionSearch drives a successful search and a directory failure.
// The sentinel password is unsealed and bound on every call. The failure is
// a *ldapdir.DirectoryError — exactly what the ldapdir client reports after
// dropping an echoing server's diagnostic text (research D4/D9).
func TestRedactionSearch(t *testing.T) {
	f := rsSetup(t, false)
	f.rsPerson("alice", "uuid-alice", "alice@example.test")
	f.rsPerson("bob", "uuid-bob", "bob@example.test")
	cts := f.rsCiphertexts(t)
	ctx := context.Background()

	res, err := f.svc.Search(ctx, actorOf(rsTenant), rsTenant, rsConnID, SearchRequest{Filter: "(mail=*)"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(res.Items))
	}
	rsNoSecret(t, "search result", res, cts...)
	rsBody(t, res)
	f.rsBound(t, 1)
	if f.dir.Binds()[0].Password != rsPW {
		t.Fatal("the stored sentinel was not used for the bind")
	}

	f.dir.InjectError(ldapfake.OpSearch, &ldapdir.DirectoryError{Code: 80})
	_, err = f.svc.Search(ctx, actorOf(rsTenant), rsTenant, rsConnID, SearchRequest{Filter: "(mail=*)"})
	if !errors.Is(err, ldapdir.ErrDirectory) {
		t.Fatalf("want a directory error, got %v", err)
	}
	rsNoSecretReason(t, "search failure", err, cts...)
	capture(t, err)

	rows := f.rsAudit(t, cts...)
	var okRow, failedRow bool
	for i := range rows {
		r := &rows[i]
		if r.EventType != string(audit.DirectorySearched) {
			continue
		}
		d := map[string]any{}
		if err := json.Unmarshal(r.Details, &d); err != nil {
			t.Fatal(err)
		}
		if r.Outcome == "ok" {
			okRow = true
			if d["count"] != float64(2) || d["filter"] != "(mail=*)" {
				t.Errorf("search details %v", d)
			}
		}
		if r.Outcome == "failed" {
			failedRow = true
			if r.Reason != "directory_error" {
				t.Errorf("failed search reason %q", r.Reason)
			}
		}
	}
	if !okRow || !failedRow {
		t.Errorf("missing directory_searched rows: ok=%v failed=%v", okRow, failedRow)
	}
}

// TestRedactionImport drives a successful import with one failing uid and a
// whole-request bind failure. Import never writes an outbox row and the
// audit counts must never carry directory data.
func TestRedactionImport(t *testing.T) {
	t.Run("created and one directory failure", func(t *testing.T) {
		f := rsSetup(t, false)
		f.rsPerson("alice", "uuid-alice", "alice@example.test")
		f.rsPerson("bob", "uuid-bob", "bob@example.test")
		cts := f.rsCiphertexts(t)

		// The third re-fetch fails with the closed shape a server echo is
		// reduced to by the ldapdir client: a code, no diagnostic text.
		f.dir.InjectError(ldapfake.OpSearch, nil, nil, &ldapdir.DirectoryError{Code: 80})
		res, err := f.svc.Import(context.Background(), actorOf(rsTenant), rsTenant, rsConnID,
			[]string{"uuid-alice", "uuid-bob", "uuid-carol"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Created) != 2 || len(res.Failed) != 1 || res.Failed[0].Reason != ReasonDirectoryError {
			t.Fatalf("res=%+v", res)
		}
		rsNoSecret(t, "import result", res, cts...)
		rsBody(t, res)
		f.rsBound(t, 1)
		if f.dir.Binds()[0].Password != rsPW {
			t.Fatal("the stored sentinel was not used for the bind")
		}
		if n := len(f.ms.Outbox); n != 0 {
			t.Fatalf("import wrote %d outbox rows; it must never send e-mail", n)
		}

		rows := f.rsAudit(t, cts...)
		var imported bool
		for i := range rows {
			r := &rows[i]
			if r.EventType != string(audit.DirectoryImported) {
				continue
			}
			imported = true
			if r.Outcome != "ok" {
				t.Errorf("import outcome %q", r.Outcome)
			}
			d := map[string]any{}
			if err := json.Unmarshal(r.Details, &d); err != nil {
				t.Fatal(err)
			}
			if d["created"] != float64(2) || d["failed"] != float64(1) || d["updated"] != float64(0) {
				t.Errorf("import counts %v", d)
			}
			if _, ok := d["created_user_ids"].([]any); !ok {
				t.Errorf("import details lack created_user_ids: %v", d)
			}
		}
		if !imported {
			t.Error("no directory_imported audit row")
		}
	})

	t.Run("bind failure refuses the import", func(t *testing.T) {
		f := rsSetup(t, false)
		cts := f.rsCiphertexts(t)
		f.dir.SetCredentials(rsBindDN, "rotated-in-directory")
		res, err := f.svc.Import(context.Background(), actorOf(rsTenant), rsTenant, rsConnID, []string{"uuid-alice"})
		if !errors.Is(err, ldapdir.ErrInvalidCredentials) {
			t.Fatalf("want ErrInvalidCredentials, got res=%+v err=%v", res, err)
		}
		rsNoSecretReason(t, "import bind failure", err, cts...)
		capture(t, err)
		if len(res.Created) != 0 || len(res.Updated) != 0 {
			t.Fatalf("a refused import wrote users: %+v", res)
		}
		rows := f.rsAudit(t, cts...)
		var failed bool
		for i := range rows {
			r := &rows[i]
			if r.EventType == string(audit.DirectoryImported) && r.Outcome == "failed" && r.Reason == "invalid_credentials" {
				failed = true
			}
		}
		if !failed {
			t.Error("no directory_imported failed row")
		}
	})
}
