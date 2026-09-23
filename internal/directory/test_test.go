package directory

// Tests first for connection testing (T025, US1): step reporting with the
// closed reasons, TLS version on success, last_test persistence for saved
// connections, stored-password reuse via connection_id within the tenant only,
// the per-tenant rate limit, the directory_connection_tested audit event and
// the absence of the password and of server text from every result and error.
//
// Helpers here carry a "tt" prefix so they cannot collide with the CRUD
// suite (directory_test.go) in the same package.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
	ttTenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	ttOther  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	ttConnID = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	ttOtherC = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"

	ttBindDN = "cn=reader,dc=example,dc=test"
	ttBaseDN = "ou=Engineering,dc=example,dc=test"
	ttURL    = "ldaps://ldap.example.test:636"

	// Sentinels: none of these may appear in a result, an error or an audit row.
	ttStoredPW = "Stored-S3ntinel-Pw-7f3a"
	ttTypedPW  = "Typed-S3ntinel-Pw-91c2"
	ttOtherPW  = "Other-Tenant-S3ntinel-Pw-55d0"
	ttServer   = "SERVER-DIAG-TEXT-e1b9"
)

var ttSecrets = []string{ttStoredPW, ttTypedPW, ttOtherPW, ttServer}

type ttFixture struct {
	svc *Service
	ms  *memstore.Store
	dir *ldapfake.Directory
	env *crypto.Envelope
	aw  *audit.Writer
	cfg config.Directory
}

type ttOpts struct {
	rate       int
	production bool
	plaintext  bool
	// wrap, when set, decorates the fake before it is handed to the service.
	wrap func(ldapdir.Directory) ldapdir.Directory
}

// ttSetup wires the service over memstore + ldapfake + cache.Memory. The
// directory has the base DN and a reader account whose password equals the
// stored one; tenant ttTenant owns connection ttConnID, tenant ttOther owns
// ttOtherC (a different password), both sealed with the documented
// associated data.
func ttSetup(t *testing.T, o ttOpts) *ttFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: ttTenant, Slug: "acme", Status: "active", Kind: "customer"})
	ms.AddTenant(store.Tenant{ID: ttOther, Slug: "other", Status: "active", Kind: "customer"})
	env, err := crypto.NewEnvelope(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Directory
	if o.rate > 0 {
		cfg.RatePerMinute = o.rate
	}
	cfg.AllowPlaintext = o.plaintext
	pol, err := ldapdir.NewTargetPolicy(cfg.Targets)
	if err != nil {
		t.Fatal(err)
	}
	dir := ldapfake.New()
	dir.Add(ldapfake.Entry{DN: "dc=example,dc=test", Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("domain")}})
	dir.Add(ldapfake.Entry{DN: ttBaseDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("organizationalUnit")}})
	dir.Add(ldapfake.Entry{DN: ttBindDN, Attrs: map[string][][]byte{"objectclass": ldapfake.Vals("person")}})
	dir.SetCredentials(ttBindDN, ttStoredPW)
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	var d ldapdir.Directory = dir
	if o.wrap != nil {
		d = o.wrap(dir)
	}
	svc := New(Deps{
		Store:      ms,
		Directory:  d,
		Envelope:   env,
		Policy:     pol,
		Cache:      cache.New(cache.NewMemory()),
		Audit:      aw,
		Config:     cfg,
		Production: o.production,
	})
	f := &ttFixture{svc: svc, ms: ms, dir: dir, env: env, aw: aw, cfg: cfg}
	f.seed(t, ttTenant, ttConnID, "Corp LDAP", ttStoredPW)
	f.seed(t, ttOther, ttOtherC, "Other LDAP", ttOtherPW)
	return f
}

func (f *ttFixture) seed(t *testing.T, tid, id, name, pw string) {
	t.Helper()
	enc, err := f.env.Encrypt([]byte(pw), []byte("ldap-bind:"+tid+":"+id))
	if err != nil {
		t.Fatal(err)
	}
	err = f.ms.InsertDirectoryConnection(context.Background(), store.DirectoryConnection{
		ID: id, TenantID: tid, Name: name, Kind: "openldap", URL: ttURL, TLSMode: ldapdir.TLSModeLDAPS,
		BindDN: ttBindDN, BindPasswordEnc: enc, BaseDN: ttBaseDN,
		AttrUID: "entryUUID", AttrEmail: "mail", AttrDisplayName: "displayName", AttrFirstName: "givenName", AttrLastName: "sn",
		SizeLimit: 500, TimeLimitSeconds: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *ttFixture) conn(t *testing.T, tid, id string) store.DirectoryConnection {
	t.Helper()
	c, err := f.ms.GetDirectoryConnection(context.Background(), tid, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tested returns the directory_connection_tested rows (after a flush).
func (f *ttFixture) tested() []store.AuditRow {
	f.aw.Flush()
	var out []store.AuditRow
	for i := range f.ms.AuditRows {
		if f.ms.AuditRows[i].EventType == string(audit.DirectoryConnectionTested) {
			out = append(out, f.ms.AuditRows[i])
		}
	}
	return out
}

func (f *ttFixture) events(typ audit.EventType) []store.AuditRow {
	f.aw.Flush()
	var out []store.AuditRow
	for i := range f.ms.AuditRows {
		if f.ms.AuditRows[i].EventType == string(typ) {
			out = append(out, f.ms.AuditRows[i])
		}
	}
	return out
}

func ttAdmin(tid string) tenantctx.Actor {
	return tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid, Roles: []string{"admin"}}
}

func ttPtr(s string) *string { return &s }

// ttInput is a valid unsaved-connection input with a typed password equal to
// the directory's (so it binds).
func ttInput() Input {
	return Input{
		Name: "Draft", Kind: "openldap", URL: ttURL, TLSMode: ldapdir.TLSModeLDAPS,
		BindDN: ttBindDN, BindPassword: ttPtr(ttStoredPW), BaseDN: ttBaseDN,
	}
}

// ttNoSecret fails when any sentinel appears in v's %+v, %#v or JSON form.
func ttNoSecret(t *testing.T, what string, v any) {
	t.Helper()
	js, _ := json.Marshal(v)
	for _, form := range []string{fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), string(js)} {
		for _, s := range ttSecrets {
			if strings.Contains(form, s) {
				t.Fatalf("%s leaks a secret or server text", what)
			}
		}
	}
}

func ttNoSecretErr(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range ttSecrets {
		if strings.Contains(err.Error(), s) || strings.Contains(fmt.Sprintf("%+v", err), s) {
			t.Fatalf("%s error leaks a secret or server text", what)
		}
	}
}

func (f *ttFixture) noSecretInAudit(t *testing.T) {
	t.Helper()
	f.aw.Flush()
	for i := range f.ms.AuditRows {
		r := &f.ms.AuditRows[i]
		ttNoSecret(t, "audit row "+r.EventType, *r)
		ttNoSecret(t, "audit details "+r.EventType, string(r.Details))
	}
}

func ttDetails(t *testing.T, r *store.AuditRow) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(r.Details, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTestSavedSuccess(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()
	before := time.Now().Add(-time.Second)
	res, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttConnID)
	after := time.Now().Add(time.Second)
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if !res.OK || res.Step != "" || res.Reason != "" {
		t.Fatalf("want ok with no step/reason, got ok=%v step=%q reason=%q", res.OK, res.Step, res.Reason)
	}
	if res.TLS == nil || res.TLS.Version != "TLS 1.3" {
		t.Fatalf("want TLS 1.3 reported, got %+v", res.TLS)
	}
	if res.DurationMS < 0 {
		t.Fatalf("duration %d", res.DurationMS)
	}
	ttNoSecret(t, "result", res)

	// The stored connection's parameters reach the directory unchanged.
	opens := f.dir.Opens()
	if len(opens) != 1 {
		t.Fatalf("opens = %d", len(opens))
	}
	p := opens[0]
	if p.URL != ttURL || p.TLSMode != ldapdir.TLSModeLDAPS || p.AllowTLS12 || p.CAPEM != "" || p.DialTimeout != f.cfg.DialTimeout {
		t.Fatalf("conn params %+v", p)
	}
	binds := f.dir.Binds()
	if len(binds) != 1 || binds[0].DN != ttBindDN || binds[0].Password != ttStoredPW {
		t.Fatal("bind must use the stored bind DN and the unsealed stored password")
	}
	if bc := f.dir.BaseChecks(); len(bc) != 1 || bc[0] != ttBaseDN {
		t.Fatalf("base checks %v", bc)
	}
	if len(f.dir.Searches()) != 0 {
		t.Fatal("a connection test must not search")
	}
	if f.dir.OpenSessions() != 0 {
		t.Fatal("session left open")
	}

	// last_test persisted.
	c := f.conn(t, ttTenant, ttConnID)
	if c.LastTestOutcome == nil || *c.LastTestOutcome != "ok" || c.LastTestAt == nil ||
		c.LastTestAt.Before(before) || c.LastTestAt.After(after) {
		t.Fatalf("last_test not persisted: %v %v", c.LastTestOutcome, c.LastTestAt)
	}

	rows := f.tested()
	if len(rows) != 1 {
		t.Fatalf("tested audit rows = %d", len(rows))
	}
	r := rows[0]
	if r.TenantID != ttTenant || r.Outcome != "ok" || r.ActorUserID == nil || *r.ActorUserID != "u-admin" || r.ActorKind != "user" {
		t.Fatalf("audit row %+v", r)
	}
	if d := ttDetails(t, &r); d["connection_id"] != ttConnID {
		t.Fatalf("audit details %v", d)
	}
	f.noSecretInAudit(t)
}

func TestTestTLSVersionReported(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	f.dir.SetTLSVersion(tls.VersionTLS12)
	in := ttInput()
	in.AllowTLS12 = true
	res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
	if err != nil || !res.OK || res.TLS == nil || res.TLS.Version != "TLS 1.2" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if p := f.dir.Opens()[0]; !p.AllowTLS12 || p.TLSMode != ldapdir.TLSModeLDAPS {
		t.Fatalf("allow_tls12 not passed through: %+v", p)
	}

	// StartTLS reports its negotiated version too.
	in = ttInput()
	in.URL, in.TLSMode = "ldap://ldap.example.test:389", ldapdir.TLSModeStartTLS
	f.dir.SetTLSVersion(tls.VersionTLS13)
	res, err = f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
	if err != nil || !res.OK || res.TLS == nil || res.TLS.Version != "TLS 1.3" {
		t.Fatalf("starttls res=%+v err=%v", res, err)
	}
}

// TestTestSteps covers every failing step with the closed reasons, including
// injected errors whose text carries server diagnostics and the password.
func TestTestSteps(t *testing.T) {
	leaky := errors.New(ttServer + ": bind as " + ttBindDN + " with " + ttStoredPW + " rejected")
	cases := []struct {
		name         string
		arrange      func(f *ttFixture, in *Input)
		step, reason string
		opened       bool // Open was reached
	}{
		{"unreachable", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrUnreachable) }, "connect", "unreachable", true},
		{"dial timeout", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrTimeout) }, "connect", "timeout", true},
		{"dial-time target refused", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrTargetRefused) }, "connect", "target_refused", true},
		{"literal ip refused before dialling", func(_ *ttFixture, in *Input) { in.URL = "ldaps://127.0.0.1:636" }, "connect", "target_refused", false},
		{"metadata ip refused before dialling", func(_ *ttFixture, in *Input) {
			in.URL, in.TLSMode = "ldap://169.254.169.254:389", ldapdir.TLSModeStartTLS
		}, "connect", "target_refused", false},
		{"port outside policy", func(_ *ttFixture, in *Input) { in.URL = "ldaps://ldap.example.test:5432" }, "connect", "target_refused", false},
		{"untrusted certificate", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrTLS) }, "tls", "tls_failed", true},
		{"starttls refused", func(f *ttFixture, in *Input) {
			in.URL, in.TLSMode = "ldap://ldap.example.test:389", ldapdir.TLSModeStartTLS
			f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrTLS)
		}, "tls", "tls_failed", true},
		{"wrong password", func(_ *ttFixture, in *Input) { in.BindPassword = ttPtr(ttTypedPW) }, "bind", "invalid_credentials", true},
		{"unknown bind dn", func(_ *ttFixture, in *Input) { in.BindDN = "cn=nobody,dc=example,dc=test" }, "bind", "invalid_credentials", true},
		{"bind timeout", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpBind, ldapdir.ErrTimeout) }, "bind", "timeout", true},
		{"bind other result code", func(f *ttFixture, _ *Input) {
			f.dir.InjectError(ldapfake.OpBind, &ldapdir.DirectoryError{Code: 53})
		}, "bind", "directory_error", true},
		{"bind server text", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpBind, leaky) }, "bind", "directory_error", true},
		{"open server text", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpOpen, leaky) }, "connect", "directory_error", true},
		{"base not found", func(_ *ttFixture, in *Input) { in.BaseDN = "ou=Nope,dc=example,dc=test" }, "search_base", "base_not_found", true},
		{"base below referral", func(f *ttFixture, in *Input) {
			f.dir.AddReferral("ou=Remote,dc=example,dc=test", "ldap://remote.example.test/")
			in.BaseDN = "ou=Remote,dc=example,dc=test"
		}, "search_base", "directory_error", true},
		{"base check timeout", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpBaseExists, ldapdir.ErrTimeout) }, "search_base", "timeout", true},
		{"base check server text", func(f *ttFixture, _ *Input) { f.dir.InjectError(ldapfake.OpBaseExists, leaky) }, "search_base", "directory_error", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ttSetup(t, ttOpts{})
			in := ttInput()
			tc.arrange(f, &in)
			res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
			if err != nil {
				t.Fatalf("a failing step is a result, not an error: %v", err)
			}
			ttNoSecretErr(t, tc.name, err)
			if res.OK || res.Step != tc.step || res.Reason != tc.reason || res.TLS != nil {
				t.Fatalf("got ok=%v step=%q reason=%q tls=%v, want step=%q reason=%q",
					res.OK, res.Step, res.Reason, res.TLS, tc.step, tc.reason)
			}
			ttNoSecret(t, "result", res)
			if got := len(f.dir.Opens()) == 1; got != tc.opened {
				t.Fatalf("opened=%v want %v", got, tc.opened)
			}
			if f.dir.OpenSessions() != 0 {
				t.Fatal("session left open after a failure")
			}
			rows := f.tested()
			if len(rows) != 1 || rows[0].Outcome != "failed" || rows[0].Reason != tc.reason {
				t.Fatalf("audit rows %+v", rows)
			}
			if d := ttDetails(t, &rows[0]); d["step"] != tc.step {
				t.Fatalf("audit details %v", d)
			}
			f.noSecretInAudit(t)
		})
	}
}

// TestTestStepOrder: a failure stops the sequence (no bind after a TLS
// failure, no base check after a failed bind).
func TestTestStepOrder(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	f.dir.InjectError(ldapfake.OpOpen, ldapdir.ErrTLS)
	if _, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, ttInput(), ""); err != nil {
		t.Fatal(err)
	}
	if len(f.dir.Binds()) != 0 || len(f.dir.BaseChecks()) != 0 {
		t.Fatal("no bind or base check after a TLS failure (no plaintext fallback)")
	}
	in := ttInput()
	in.BindPassword = ttPtr(ttTypedPW)
	if _, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, ""); err != nil {
		t.Fatal(err)
	}
	if len(f.dir.BaseChecks()) != 0 {
		t.Fatal("no base check after a failed bind")
	}
	if len(f.dir.Opens()) != 2 {
		t.Fatalf("opens %d", len(f.dir.Opens()))
	}
}

func TestTestSavedFailurePersistsOutcome(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()
	f.dir.SetCredentials(ttBindDN, "rotated-in-directory")
	res, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttConnID)
	if err != nil || res.OK || res.Step != "bind" || res.Reason != "invalid_credentials" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	c := f.conn(t, ttTenant, ttConnID)
	if c.LastTestOutcome == nil || *c.LastTestOutcome != "invalid_credentials" || c.LastTestAt == nil {
		t.Fatalf("last_test outcome %v", c.LastTestOutcome)
	}
	// A later success overwrites it.
	f.dir.SetCredentials(ttBindDN, ttStoredPW)
	if res, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttConnID); err != nil || !res.OK {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c := f.conn(t, ttTenant, ttConnID); *c.LastTestOutcome != "ok" {
		t.Fatalf("last_test outcome %v", *c.LastTestOutcome)
	}
	// Every outcome stored is in the data-model vocabulary.
	f.dir.InjectError(ldapfake.OpOpen, errors.New(ttServer))
	if res, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttConnID); err != nil || res.Reason != "directory_error" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c := f.conn(t, ttTenant, ttConnID); *c.LastTestOutcome != "directory_error" {
		t.Fatalf("last_test outcome %v", *c.LastTestOutcome)
	}
	f.noSecretInAudit(t)
}

// TestTestUnsavedDoesNotPersist: an unsaved test never writes last_test, even
// when it borrows a saved connection's password.
func TestTestUnsavedDoesNotPersist(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	in := ttInput()
	in.BindPassword = nil
	res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, ttConnID)
	if err != nil || !res.OK {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c := f.conn(t, ttTenant, ttConnID); c.LastTestOutcome != nil || c.LastTestAt != nil {
		t.Fatal("an unsaved test must not persist last_test")
	}
}

func TestTestReusesStoredPassword(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()

	// Omitted password + connection_id → the stored one is used, with the
	// edited (unsaved) settings.
	in := ttInput()
	in.BindPassword = nil
	in.BaseDN = "dc=example,dc=test"
	res, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ttConnID)
	if err != nil || !res.OK {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if b := f.dir.Binds(); len(b) != 1 || b[0].Password != ttStoredPW {
		t.Fatal("stored password not reused")
	}
	if bc := f.dir.BaseChecks(); len(bc) != 1 || bc[0] != "dc=example,dc=test" {
		t.Fatalf("unsaved base not used: %v", bc)
	}

	// A typed password wins over the stored one.
	in.BindPassword = ttPtr(ttTypedPW)
	res, err = f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ttConnID)
	if err != nil || res.OK || res.Reason != "invalid_credentials" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if b := f.dir.Binds(); len(b) != 2 || b[1].Password != ttTypedPW {
		t.Fatal("typed password must be used when present")
	}

	// Omitted password without a connection_id: refused before any dial
	// (no anonymous bind).
	in.BindPassword = nil
	_, err = f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	// An empty typed password is refused the same way.
	in.BindPassword = ttPtr("")
	_, err = f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ttConnID)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("empty password: want ErrValidation, got %v", err)
	}
	if n := len(f.dir.Opens()); n != 2 {
		t.Fatalf("refused inputs must not dial, opens=%d", n)
	}
	f.noSecretInAudit(t)
}

// TestTestStoredPasswordTenantScoped: connection_id is resolved only inside
// the caller's tenant; another tenant's id behaves as not found and is audited
// as cross_tenant_refused, and its password is never used.
func TestTestStoredPasswordTenantScoped(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()
	f.dir.SetCredentials(ttBindDN, ttOtherPW) // would succeed if tenant B's password leaked into A's test

	in := ttInput()
	in.BindPassword = nil
	res, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ttOtherC)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got res=%+v err=%v", res, err)
	}
	ttNoSecretErr(t, "cross-tenant", err)
	ttNoSecret(t, "cross-tenant result", res)
	if len(f.dir.Opens()) != 0 || len(f.dir.Binds()) != 0 {
		t.Fatal("cross-tenant connection_id must not dial or bind")
	}
	if x := f.events(audit.CrossTenantRefused); len(x) != 1 || (x[0].TenantID != ttTenant && x[0].TenantID != ttOther) {
		t.Fatalf("cross_tenant_refused rows %+v", x)
	}

	// The saved-connection route behaves the same.
	if _, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttOtherC); !errors.Is(err, ErrNotFound) {
		t.Fatalf("saved cross-tenant: %v", err)
	}
	if len(f.dir.Opens()) != 0 {
		t.Fatal("saved cross-tenant test dialled")
	}
	if c := f.conn(t, ttOther, ttOtherC); c.LastTestOutcome != nil {
		t.Fatal("other tenant's last_test changed")
	}
	if x := f.events(audit.CrossTenantRefused); len(x) != 2 {
		t.Fatalf("cross_tenant_refused rows = %d", len(x))
	}

	// Unknown ids are plain not found, with no cross-tenant audit.
	const ghost = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"
	if _, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ghost); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ghost); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown saved id: %v", err)
	}
	if x := f.events(audit.CrossTenantRefused); len(x) != 2 {
		t.Fatalf("unknown id audited as cross-tenant: %d", len(x))
	}
	if len(f.dir.Opens()) != 0 {
		t.Fatal("unknown id dialled")
	}
	f.noSecretInAudit(t)
}

// TestTestSealedToConnection: the stored ciphertext is bound to its tenant and
// connection id; a row whose ciphertext was moved from another connection
// cannot be used and never binds.
func TestTestSealedToConnection(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()
	moved := f.conn(t, ttOther, ttOtherC).BindPasswordEnc
	const stolen = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4caa"
	c := f.conn(t, ttTenant, ttConnID)
	c.ID, c.Name, c.BindPasswordEnc = stolen, "Moved", moved
	if err := f.ms.InsertDirectoryConnection(ctx, c); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, stolen)
	if err == nil && res.OK {
		t.Fatal("a moved ciphertext was accepted")
	}
	ttNoSecretErr(t, "moved ciphertext", err)
	ttNoSecret(t, "moved ciphertext result", res)
	for _, b := range f.dir.Binds() {
		if b.Password == ttOtherPW {
			t.Fatal("another connection's password reached Bind")
		}
	}
}

func TestTestRateLimitPerTenant(t *testing.T) {
	f := ttSetup(t, ttOpts{rate: 3})
	ctx := context.Background()
	for i := range 3 {
		if res, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, ttInput(), ""); err != nil || !res.OK {
			t.Fatalf("call %d: res=%+v err=%v", i, res, err)
		}
	}
	opens := len(f.dir.Opens())
	_, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, ttInput(), "")
	if !errors.Is(err, ErrRateLimited) || err.Error() != "rate_limited" {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if _, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, ttConnID); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("saved test not rate limited: %v", err)
	}
	if len(f.dir.Opens()) != opens {
		t.Fatal("a rate-limited test must not dial")
	}
	if c := f.conn(t, ttTenant, ttConnID); c.LastTestOutcome != nil {
		t.Fatal("a rate-limited test must not persist last_test")
	}
	refused := 0
	rows := f.tested()
	for i := range rows {
		if r := &rows[i]; r.Outcome == "refused" && r.Reason == "rate_limited" && r.TenantID == ttTenant {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("rate_limited audit rows = %d", refused)
	}

	// The limit is per tenant: tenant B is unaffected.
	if res, err := f.svc.TestSaved(ctx, ttAdmin(ttOther), ttOther, ttOtherC); err != nil || res.Reason == "rate_limited" {
		t.Fatalf("other tenant limited: res=%+v err=%v", res, err)
	}
}

func TestTestValidationBeforeDial(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Input)
		want   error
	}{
		{"userinfo in url", func(in *Input) { in.URL = "ldaps://reader:" + ttStoredPW + "@ldap.example.test:636" }, ldapdir.ErrInvalidURL},
		{"http scheme", func(in *Input) { in.URL = "https://ldap.example.test" }, ldapdir.ErrInvalidURL},
		{"scheme vs tls mode", func(in *Input) { in.URL = "ldap://ldap.example.test:389" }, ldapdir.ErrInvalidURL},
		{"garbage ca", func(in *Input) {
			in.CAPEM = "-----BEGIN CERTIFICATE-----\n" + ttServer + "\n-----END CERTIFICATE-----\n"
		}, ldapdir.ErrInvalidCA},
		{"unknown tls mode", func(in *Input) { in.TLSMode = "none" }, ErrValidation},
		{"bad bind dn", func(in *Input) { in.BindDN = "not a dn" }, ErrValidation},
		{"bad base dn", func(in *Input) { in.BaseDN = "=,=" }, ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ttSetup(t, ttOpts{})
			in := ttInput()
			tc.mutate(&in)
			res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got res=%+v err=%v", tc.want, res, err)
			}
			ttNoSecretErr(t, tc.name, err)
			ttNoSecret(t, "result", res)
			if len(f.dir.Opens()) != 0 {
				t.Fatal("invalid input dialled")
			}
			f.noSecretInAudit(t)
		})
	}
}

func TestTestPlaintext(t *testing.T) {
	in := ttInput()
	in.URL, in.TLSMode = "ldap://ldap.example.test:389", ldapdir.TLSModePlain

	// Production refuses plaintext even with the opt-out set (config
	// validation refuses that combination too; the service must not rely on it).
	f := ttSetup(t, ttOpts{production: true, plaintext: true})
	_, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
	if !errors.Is(err, ErrInsecureTransport) || err.Error() != "insecure_transport" {
		t.Fatalf("production: want ErrInsecureTransport, got %v", err)
	}
	if len(f.dir.Opens()) != 0 {
		t.Fatal("plaintext dialled in production")
	}

	// Non-production without the opt-out: refused as well.
	f = ttSetup(t, ttOpts{})
	if _, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, ""); !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("dev without opt-out: %v", err)
	}

	// Development with allow_plaintext: runs, and reports no TLS.
	f = ttSetup(t, ttOpts{plaintext: true})
	res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, in, "")
	if err != nil || !res.OK || res.TLS != nil {
		t.Fatalf("dev plaintext: res=%+v err=%v", res, err)
	}
	if p := f.dir.Opens()[0]; p.TLSMode != ldapdir.TLSModePlain {
		t.Fatalf("params %+v", p)
	}
}

// TestTestTLSStateRequired: an ldaps/StartTLS session that reports no
// completed handshake is a TLS failure, never a silent plaintext success.
func TestTestTLSStateRequired(t *testing.T) {
	f := ttSetup(t, ttOpts{wrap: func(d ldapdir.Directory) ldapdir.Directory { return plainSessionDir{d} }})
	res, err := f.svc.Test(context.Background(), ttAdmin(ttTenant), ttTenant, ttInput(), "")
	if err != nil || res.OK || res.Step != "tls" || res.Reason != "tls_failed" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.dir.Binds()) != 0 {
		t.Fatal("bound over a session without TLS")
	}
	if f.dir.OpenSessions() != 0 {
		t.Fatal("session left open")
	}
}

// plainSessionDir opens fake sessions as plain regardless of the requested
// TLS mode, modelling a client that failed to negotiate TLS.
type plainSessionDir struct{ d ldapdir.Directory }

func (p plainSessionDir) Open(ctx context.Context, c ldapdir.ConnParams) (ldapdir.Session, error) {
	c.TLSMode = ldapdir.TLSModePlain
	return p.d.Open(ctx, c)
}

// TestTestCtxDeadline: a directory slower than the caller's deadline yields a
// timeout result, promptly, with the session closed.
func TestTestCtxDeadline(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	f.dir.SetDelay(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, ttInput(), "")
	if time.Since(start) > 2*time.Second {
		t.Fatal("test ignored the ctx deadline")
	}
	if err != nil || res.OK || res.Reason != "timeout" || res.Step != "bind" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if f.dir.OpenSessions() != 0 {
		t.Fatal("session left open")
	}
}

// TestTestStoreFailure: a failure to persist last_test is an internal error
// that carries neither the password nor store text into the result.
func TestTestStoreFailure(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	f.ms.FailNext("SetDirectoryConnectionTest")
	res, err := f.svc.TestSaved(context.Background(), ttAdmin(ttTenant), ttTenant, ttConnID)
	if err == nil {
		t.Fatalf("store failure swallowed: %+v", res)
	}
	ttNoSecretErr(t, "store failure", err)
	f.noSecretInAudit(t)
}
