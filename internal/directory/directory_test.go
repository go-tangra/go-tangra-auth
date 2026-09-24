package directory

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

// Connection CRUD (US1, research D3/D4/D5/D6/D13/D14/D15). The bind password
// used here is the redaction-scan sentinel: it must never appear in a view,
// an error, an audit row or the test log.

const (
	crudTenantA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	crudTenantB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	crudPW      = "LDAP-MARKER-PW-crud-1"
	crudPW2     = "LDAP-MARKER-PW-crud-2"
)

type crudFixture struct {
	svc *Service
	ms  *memstore.Store
	env *crypto.Envelope
	aw  *audit.Writer
	fd  *ldapfake.Directory
}

type crudOpt func(*Deps)

func crudProduction(d *Deps)     { d.Production = true }
func crudAllowPlaintext(d *Deps) { d.Config.AllowPlaintext = true }
func crudMaxConns(n int) crudOpt { return func(d *Deps) { d.Config.MaxConnectionsPerTenant = n } }

func newCRUD(t *testing.T, opts ...crudOpt) *crudFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: crudTenantA, Slug: "acme", Status: "active", Kind: "customer"})
	ms.AddTenant(store.Tenant{ID: crudTenantB, Slug: "globex", Status: "active", Kind: "customer"})
	env, err := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Directory
	pol, err := ldapdir.NewTargetPolicy(config.DirectoryTargets{DenyCIDRs: []string{"10.0.0.0/8"}, AllowedPorts: cfg.Targets.AllowedPorts})
	if err != nil {
		t.Fatal(err)
	}
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	fd := ldapfake.New()
	d := Deps{Store: ms, Directory: fd, Envelope: env, Policy: pol, Config: cfg, Cache: cache.New(cache.NewMemory()), Audit: aw, Now: time.Now}
	for _, o := range opts {
		o(&d)
	}
	return &crudFixture{svc: New(d), ms: ms, env: env, aw: aw, fd: fd}
}

func sp(s string) *string { return &s }
func ip(n int) *int       { return &n }
func bp(b bool) *bool     { return &b }

func actorOf(tid string) tenantctx.Actor {
	return tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", TenantID: tid}
}

// validInput is a complete, valid create input (AD over ldaps).
func validInput(name string) Input {
	return Input{
		Name: sp(name), Kind: sp("active_directory"), URL: sp("ldaps://dc1.corp.example:636"), TLSMode: sp("ldaps"),
		BindDN: sp("cn=svc-freya,ou=Service,dc=corp,dc=example"), BindPassword: sp(crudPW),
		BaseDN: sp("ou=People,dc=corp,dc=example"),
	}
}

func (f *crudFixture) create(t *testing.T, tid string, in Input) View { //nolint:gocritic // Input is passed by value like Service.Create
	t.Helper()
	v, err := f.svc.Create(context.Background(), actorOf(tid), tid, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return v
}

func (f *crudFixture) row(t *testing.T, tid, id string) store.DirectoryConnection {
	t.Helper()
	c, err := f.ms.GetDirectoryConnection(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("stored row: %v", err)
	}
	return c
}

func (f *crudFixture) auditRows(t *testing.T) []store.AuditRow {
	t.Helper()
	f.aw.Flush()
	return append([]store.AuditRow(nil), f.ms.AuditRows...)
}

func bindAD(tid, id string) []byte { return []byte("ldap-bind:" + tid + ":" + id) }

// capture writes what a test observed to $FREYA_CAPTURE_DIR for the redaction
// scan (scripts/redaction-scan.sh); a no-op otherwise.
func capture(t *testing.T, v any) {
	t.Helper()
	dir := os.Getenv("FREYA_CAPTURE_DIR")
	if dir == "" {
		return
	}
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	fh, err := os.OpenFile(filepath.Join(dir, "directory-"+name+".txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	if err, ok := v.(error); ok {
		v = err.Error()
	}
	_, _ = fmt.Fprintf(fh, "%+v\n", v)
}

// assertNoSecret fails when s contains the password, any form of the stored
// ciphertext, or PEM armour. It never prints s (the scan greps the log).
func assertNoSecret(t *testing.T, what, s string, ciphertexts ...[]byte) {
	t.Helper()
	for _, pw := range []string{crudPW, crudPW2, "LDAP-MARKER-PW-"} {
		if strings.Contains(s, pw) {
			t.Errorf("%s contains the bind password", what)
		}
	}
	for _, ct := range ciphertexts {
		if len(ct) == 0 {
			continue
		}
		for _, enc := range []string{string(ct), base64.StdEncoding.EncodeToString(ct), base64.RawURLEncoding.EncodeToString(ct), hex.EncodeToString(ct)} {
			if strings.Contains(s, enc) {
				t.Errorf("%s contains the sealed password", what)
			}
		}
	}
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestErrorVocabulary(t *testing.T) {
	for err, want := range map[error]string{ErrValidation: "validation_failed", ErrInsecureTransport: "insecure_transport", ErrDuplicate: "duplicate", ErrLimitReached: "limit_reached", ErrNotFound: "not_found"} {
		if err.Error() != want {
			t.Errorf("error text %q, want %q", err.Error(), want)
		}
	}
}

func TestCreateSealsBindPassword(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	v := f.create(t, crudTenantA, validInput("Corp AD"))
	if v.ID == "" || !tenantctx.ValidTenantID(v.ID) || !v.BindPasswordSet {
		t.Fatalf("view: id=%q bind_password_set=%v", v.ID, v.BindPasswordSet)
	}
	row := f.row(t, crudTenantA, v.ID)
	if len(row.BindPasswordEnc) == 0 || bytes.Contains(row.BindPasswordEnc, []byte(crudPW)) {
		t.Fatal("password must be stored sealed")
	}
	if row.CreatedBy == nil || *row.CreatedBy != actorOf(crudTenantA).UserID {
		t.Fatal("created_by must be the actor")
	}
	pt, err := f.env.Decrypt(row.BindPasswordEnc, bindAD(crudTenantA, v.ID))
	if err != nil || string(pt) != crudPW {
		t.Fatalf("ciphertext must open with ldap-bind:<tenant>:<id> (err=%v)", err)
	}

	// The same ciphertext does not open for another connection or tenant.
	other := f.create(t, crudTenantA, validInput("Corp AD 2"))
	foreign := f.create(t, crudTenantB, validInput("Globex AD"))
	for _, ad := range [][]byte{
		bindAD(crudTenantA, other.ID),
		bindAD(crudTenantB, v.ID),
		bindAD(crudTenantB, foreign.ID),
		[]byte(crudTenantA + ":" + v.ID),
		nil,
	} {
		if _, err := f.env.Decrypt(row.BindPasswordEnc, ad); err == nil {
			t.Fatalf("ciphertext opened under associated data %q", ad)
		}
	}
	// Copying the ciphertext into another connection's row makes that row
	// unreadable under its own associated data.
	o := f.row(t, crudTenantA, other.ID)
	o.BindPasswordEnc = row.BindPasswordEnc
	if err := f.ms.UpdateDirectoryConnection(ctx, o); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Decrypt(f.row(t, crudTenantA, other.ID).BindPasswordEnc, bindAD(crudTenantA, other.ID)); err == nil {
		t.Fatal("moved ciphertext must not open for another connection")
	}
	// Two connections with the same password get different ciphertexts.
	if bytes.Equal(row.BindPasswordEnc, f.row(t, crudTenantB, foreign.ID).BindPasswordEnc) {
		t.Fatal("ciphertexts must differ per connection")
	}
}

func TestViewsNeverContainPassword(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	in := validInput("Corp AD")
	in.CAPEM = sp(testCAPEM(t))
	created := f.create(t, crudTenantA, in)
	ct := f.row(t, crudTenantA, created.ID).BindPasswordEnc

	// The view type carries no password or ciphertext field at all.
	vt := reflect.TypeOf(View{})
	for i := 0; i < vt.NumField(); i++ {
		fl := vt.Field(i)
		if strings.Contains(strings.ToLower(fl.Name), "password") && fl.Name != "BindPasswordSet" {
			t.Errorf("View field %s may carry the password", fl.Name)
		}
		if fl.Type == reflect.TypeOf([]byte(nil)) {
			t.Errorf("View field %s is a byte slice", fl.Name)
		}
	}

	got, err := f.svc.Get(ctx, a, crudTenantA, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.BindPasswordSet || !got.CAPEMSet || got.CAPEM == "" {
		t.Fatalf("get view: bind_password_set=%v ca_pem_set=%v ca_pem present=%v", got.BindPasswordSet, got.CAPEMSet, got.CAPEM != "")
	}
	list, err := f.svc.List(ctx, a, crudTenantA)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if list[0].CAPEM != "" || !list[0].CAPEMSet {
		t.Fatal("the CA PEM itself is returned only by Get")
	}
	updated, err := f.svc.Update(ctx, a, crudTenantA, created.ID, Input{BindPassword: sp(crudPW2)})
	if err != nil {
		t.Fatal(err)
	}
	ct2 := f.row(t, crudTenantA, created.ID).BindPasswordEnc

	for name, v := range map[string]View{"create": created, "get": got, "list": list[0], "update": updated} {
		js, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, name+" view (json)", string(js), ct, ct2)
		assertNoSecret(t, name+" view (%+v)", fmt.Sprintf("%+v %#v", v, v), ct, ct2)
		var m map[string]any
		if err := json.Unmarshal(js, &m); err != nil {
			t.Fatal(err)
		}
		if m["bind_password_set"] != true {
			t.Errorf("%s view: bind_password_set must be true", name)
		}
		for k := range m {
			if strings.Contains(k, "password") && k != "bind_password_set" {
				t.Errorf("%s view has key %q", name, k)
			}
		}
	}
	// The list view has exactly the DirectoryConnection schema (contracts §A).
	js, _ := json.Marshal(list[0])
	var m map[string]any
	_ = json.Unmarshal(js, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"allow_tls12", "attributes", "base_dn", "base_filter", "bind_dn", "bind_password_set", "ca_pem_set", "created_at", "id", "kind",
		"last_test", "name", "size_limit", "time_limit_seconds", "tls_mode", "updated_at", "url"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("list view keys %v, want %v", keys, want)
	}
	if m["last_test"] != nil {
		t.Error("a never-tested connection has last_test null")
	}
	attrs, _ := m["attributes"].(map[string]any)
	for _, k := range []string{"uid", "email", "display_name", "first_name", "last_name"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("attributes.%s missing", k)
		}
	}
	capture(t, list[0])
	capture(t, updated)
}

func TestUpdatePassword(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	v := f.create(t, crudTenantA, validInput("Corp AD"))
	before := f.row(t, crudTenantA, v.ID).BindPasswordEnc

	// No password in the update: the ciphertext is kept byte for byte.
	up, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{Name: sp("Corp AD (renamed)")})
	if err != nil || up.Name != "Corp AD (renamed)" || !up.BindPasswordSet {
		t.Fatalf("rename: %+v %v", up.Name, err)
	}
	row := f.row(t, crudTenantA, v.ID)
	if !bytes.Equal(row.BindPasswordEnc, before) {
		t.Fatal("update without a password must keep the stored ciphertext")
	}
	// A partial update leaves every other field as it was.
	if row.URL != *validInput("").URL || row.BindDN != *validInput("").BindDN || row.BaseDN != *validInput("").BaseDN || row.Kind != "active_directory" {
		t.Fatalf("partial update changed other fields: %+v", row.URL)
	}
	if row.UpdatedBy == nil || *row.UpdatedBy != a.UserID {
		t.Fatal("updated_by must be the actor")
	}

	// Empty password is refused (no anonymous binds) and nothing changes.
	for _, empty := range []string{"", "   "} {
		_, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{BindPassword: sp(empty)})
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("empty password on update: %v", err)
		}
	}
	if !bytes.Equal(f.row(t, crudTenantA, v.ID).BindPasswordEnc, before) {
		t.Fatal("refused update changed the ciphertext")
	}

	// A new password is sealed again under the same associated data.
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{BindPassword: sp(crudPW2)}); err != nil {
		t.Fatal(err)
	}
	after := f.row(t, crudTenantA, v.ID).BindPasswordEnc
	pt, err := f.env.Decrypt(after, bindAD(crudTenantA, v.ID))
	if err != nil || string(pt) != crudPW2 || bytes.Equal(after, before) {
		t.Fatalf("new password must be sealed with ldap-bind:<tenant>:<id> (err=%v)", err)
	}

	// Unknown id → not found.
	if _, err := f.svc.Update(ctx, a, crudTenantA, store.NewID(), Input{Name: sp("x")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestCreateRequiresPassword(t *testing.T) {
	f := newCRUD(t)
	for name, pw := range map[string]*string{"missing": nil, "empty": sp(""), "blank": sp("  ")} {
		in := validInput("Corp " + name)
		in.BindPassword = pw
		if _, err := f.svc.Create(context.Background(), actorOf(crudTenantA), crudTenantA, in); !errors.Is(err, ErrValidation) {
			t.Errorf("%s password: %v", name, err)
		}
	}
	if n, _ := f.ms.CountDirectoryConnections(context.Background(), crudTenantA); n != 0 {
		t.Fatalf("refused creates stored %d rows", n)
	}
}

func TestPlaintextTransport(t *testing.T) {
	plain := func(name string) Input {
		in := validInput(name)
		in.URL, in.TLSMode = sp("ldap://ldap.corp.example:389"), sp("plain")
		return in
	}
	cases := []struct {
		name string
		opts []crudOpt
		ok   bool
	}{
		{"production", []crudOpt{crudProduction}, false},
		{"production even with allow_plaintext", []crudOpt{crudProduction, crudAllowPlaintext}, false},
		{"development without opt-out", nil, false},
		{"development with allow_plaintext", []crudOpt{crudAllowPlaintext}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCRUD(t, tc.opts...)
			ctx := context.Background()
			a := actorOf(crudTenantA)
			v, err := f.svc.Create(ctx, a, crudTenantA, plain("Dev LDAP"))
			if tc.ok {
				if err != nil || v.TLSMode != "plain" {
					t.Fatalf("plain with dev opt-out: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInsecureTransport) {
				t.Fatalf("plain: %v", err)
			}
			// StartTLS and ldaps are always fine; switching an existing
			// connection to plain is refused the same way.
			in := validInput("Corp StartTLS")
			in.URL, in.TLSMode = sp("ldap://ldap.corp.example:389"), sp("starttls")
			sv := f.create(t, crudTenantA, in)
			if _, err := f.svc.Update(ctx, a, crudTenantA, sv.ID, Input{TLSMode: sp("plain")}); !errors.Is(err, ErrInsecureTransport) {
				t.Fatalf("update to plain: %v", err)
			}
			if r := f.row(t, crudTenantA, sv.ID); r.TLSMode != "starttls" {
				t.Fatal("refused update changed tls_mode")
			}
			var refused bool
			for _, r := range f.auditRows(t) {
				if r.EventType == string(audit.DirectoryConnectionCreated) && r.Outcome == "refused" && r.Reason == "insecure_transport" {
					refused = true
				}
			}
			if !refused {
				t.Error("plaintext refusal must be audited (outcome refused, reason insecure_transport)")
			}
		})
	}
}

func TestCreateValidation(t *testing.T) {
	longDN := "cn=" + strings.Repeat("a", 1100) + ",dc=example"
	cases := []struct {
		name   string
		mutate func(*Input)
		want   error
	}{
		{"empty name", func(in *Input) { in.Name = sp("") }, ErrValidation},
		{"blank name", func(in *Input) { in.Name = sp("   ") }, ErrValidation},
		{"name too long", func(in *Input) { in.Name = sp(strings.Repeat("n", 81)) }, ErrValidation},
		{"missing name", func(in *Input) { in.Name = nil }, ErrValidation},
		{"unknown kind", func(in *Input) { in.Kind = sp("novell") }, ErrValidation},
		{"missing kind", func(in *Input) { in.Kind = nil }, ErrValidation},
		{"unknown tls mode", func(in *Input) { in.TLSMode = sp("none") }, ErrValidation},
		{"missing tls mode", func(in *Input) { in.TLSMode = nil }, ErrValidation},

		{"missing url", func(in *Input) { in.URL = nil }, ldapdir.ErrInvalidURL},
		{"http scheme", func(in *Input) { in.URL = sp("https://dc1.corp.example") }, ldapdir.ErrInvalidURL},
		{"userinfo", func(in *Input) { in.URL = sp("ldaps://admin:" + crudPW + "@dc1.corp.example:636") }, ldapdir.ErrInvalidURL},
		{"path", func(in *Input) { in.URL = sp("ldaps://dc1.corp.example:636/dc=corp") }, ldapdir.ErrInvalidURL},
		{"query", func(in *Input) { in.URL = sp("ldaps://dc1.corp.example?x=1") }, ldapdir.ErrInvalidURL},
		{"no host", func(in *Input) { in.URL = sp("ldaps://:636") }, ldapdir.ErrInvalidURL},
		{"url too long", func(in *Input) {
			in.URL = sp("ldaps://" + strings.Repeat("a", 60) + "." + strings.Repeat("b.", 250) + "example")
		}, ldapdir.ErrInvalidURL},
		{"ldaps url with starttls", func(in *Input) { in.TLSMode = sp("starttls") }, ldapdir.ErrInvalidURL},
		{"ldap url with ldaps mode", func(in *Input) { in.URL = sp("ldap://dc1.corp.example:389") }, ldapdir.ErrInvalidURL},

		{"port outside policy", func(in *Input) { in.URL = sp("ldaps://dc1.corp.example:5432") }, ldapdir.ErrTargetRefused},
		{"loopback literal", func(in *Input) { in.URL = sp("ldaps://127.0.0.1:636") }, ldapdir.ErrTargetRefused},
		{"metadata literal", func(in *Input) { in.URL = sp("ldaps://169.254.169.254:636") }, ldapdir.ErrTargetRefused},
		{"denied cidr literal", func(in *Input) { in.URL = sp("ldaps://10.1.2.3:636") }, ldapdir.ErrTargetRefused},

		{"garbage ca", func(in *Input) { in.CAPEM = sp("not a certificate") }, ldapdir.ErrInvalidCA},
		{"key instead of ca", func(in *Input) {
			in.CAPEM = sp(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})))
		}, ldapdir.ErrInvalidCA},
		{"ca too large", func(in *Input) { in.CAPEM = sp(strings.Repeat("A", ldapdir.MaxCAPEMBytes+1)) }, ldapdir.ErrInvalidCA},

		{"missing bind dn", func(in *Input) { in.BindDN = nil }, ErrValidation},
		{"empty bind dn", func(in *Input) { in.BindDN = sp("") }, ErrValidation},
		{"bind dn not a dn", func(in *Input) { in.BindDN = sp("svc-freya") }, ErrValidation},
		{"bind dn empty rdn", func(in *Input) { in.BindDN = sp("cn=svc,,dc=corp") }, ErrValidation},
		{"bind dn too long", func(in *Input) { in.BindDN = sp(longDN) }, ErrValidation},
		{"missing base dn", func(in *Input) { in.BaseDN = nil }, ErrValidation},
		{"empty base dn (root DSE)", func(in *Input) { in.BaseDN = sp("") }, ErrValidation},
		{"base dn not a dn", func(in *Input) { in.BaseDN = sp("People") }, ErrValidation},
		{"base dn bad attribute", func(in *Input) { in.BaseDN = sp("ou=People,=corp") }, ErrValidation},
		{"base dn too long", func(in *Input) { in.BaseDN = sp(longDN) }, ErrValidation},

		{"unbalanced base filter", func(in *Input) { in.BaseFilter = sp("(objectClass=person") }, ldapdir.ErrInvalidFilter},
		{"injection base filter", func(in *Input) { in.BaseFilter = sp("(objectClass=*))(|(uid=*)") }, ldapdir.ErrInvalidFilter},
		{"bare base filter", func(in *Input) { in.BaseFilter = sp("objectClass") }, ldapdir.ErrInvalidFilter},
		{"base filter too long", func(in *Input) { in.BaseFilter = sp("(cn=" + strings.Repeat("a", 4100) + ")") }, ldapdir.ErrInvalidFilter},

		{"size limit zero", func(in *Input) { in.SizeLimit = ip(0) }, ErrValidation},
		{"size limit above max", func(in *Input) { in.SizeLimit = ip(1001) }, ErrValidation},
		{"time limit zero", func(in *Input) { in.TimeLimitSeconds = ip(0) }, ErrValidation},
		{"time limit above max", func(in *Input) { in.TimeLimitSeconds = ip(61) }, ErrValidation},
		{"attribute with space", func(in *Input) { in.Attributes = &Mapping{UID: "object GUID"} }, ErrValidation},
		{"attribute wildcard", func(in *Input) { in.Attributes = &Mapping{Email: "*"} }, ErrValidation},
		{"attribute filter chars", func(in *Input) { in.Attributes = &Mapping{DisplayName: "cn)(uid=*"} }, ErrValidation},
		{"attribute too long", func(in *Input) { in.Attributes = &Mapping{FirstName: "g" + strings.Repeat("x", 64)} }, ErrValidation},
	}
	f := newCRUD(t)
	a := actorOf(crudTenantA)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput("Corp AD")
			tc.mutate(&in)
			_, err := f.svc.Create(context.Background(), a, crudTenantA, in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			assertNoSecret(t, "error", err.Error())
			capture(t, err)
		})
	}
	if n, _ := f.ms.CountDirectoryConnections(context.Background(), crudTenantA); n != 0 {
		t.Fatalf("refused creates stored %d rows", n)
	}
	if len(f.fd.Opens()) != 0 {
		t.Fatal("create must not contact the directory")
	}
}

func TestUpdateValidation(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	v := f.create(t, crudTenantA, validInput("Corp AD"))
	before := f.row(t, crudTenantA, v.ID)
	for name, tc := range map[string]struct {
		in   Input
		want error
	}{
		"url":         {Input{URL: sp("ldaps://dc1.corp.example:636/x")}, ldapdir.ErrInvalidURL},
		"port":        {Input{URL: sp("ldaps://dc1.corp.example:22")}, ldapdir.ErrTargetRefused},
		"ca":          {Input{CAPEM: sp("garbage")}, ldapdir.ErrInvalidCA},
		"bind dn":     {Input{BindDN: sp("nope")}, ErrValidation},
		"base dn":     {Input{BaseDN: sp("")}, ErrValidation},
		"base filter": {Input{BaseFilter: sp("(|(a=b)")}, ldapdir.ErrInvalidFilter},
		"name":        {Input{Name: sp("")}, ErrValidation},
		"size limit":  {Input{SizeLimit: ip(5000)}, ErrValidation},
	} {
		if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	if after := f.row(t, crudTenantA, v.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("refused updates changed the stored row")
	}
}

func TestValidFieldsAndDefaults(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	caPEM := testCAPEM(t)
	raw := "(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	cf, err := ldap.CompileFilter(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := ldap.DecompileFilter(cf)
	if err != nil {
		t.Fatal(err)
	}
	in := validInput("Corp AD")
	in.URL = sp("ldaps://[2001:db8::10]:3269")
	in.CAPEM, in.AllowTLS12, in.BaseFilter = sp(caPEM), bp(true), sp(raw)
	in.SizeLimit, in.TimeLimitSeconds = ip(1000), ip(60)
	v := f.create(t, crudTenantA, in)
	if v.BaseFilter != canonical || !v.AllowTLS12 || !v.CAPEMSet || v.SizeLimit != 1000 || v.TimeLimitSeconds != 60 || v.URL != "ldaps://[2001:db8::10]:3269" {
		t.Fatalf("view: filter=%q tls12=%v ca=%v size=%d time=%d url=%q", v.BaseFilter, v.AllowTLS12, v.CAPEMSet, v.SizeLimit, v.TimeLimitSeconds, v.URL)
	}
	if r := f.row(t, crudTenantA, v.ID); r.BaseFilter != canonical || r.CAPEM != caPEM {
		t.Fatal("stored row must hold the canonical filter and the CA bundle")
	}

	// Defaults: empty base filter, size 500, time 15 s, no CA (system roots),
	// TLS 1.3 only.
	d := f.create(t, crudTenantA, validInput("Corp AD defaults"))
	if d.BaseFilter != "" || d.SizeLimit != 500 || d.TimeLimitSeconds != 15 || d.CAPEMSet || d.AllowTLS12 || d.LastTest != nil {
		t.Fatalf("defaults: %+v", d)
	}
	// A deployment with a lower max_size_limit caps the default.
	g := newCRUD(t, func(dp *Deps) { dp.Config.MaxSizeLimit = 100; dp.Config.MaxTimeLimit = 10 * time.Second })
	gv := g.create(t, crudTenantA, validInput("Capped"))
	if gv.SizeLimit != 100 || gv.TimeLimitSeconds != 10 {
		t.Fatalf("capped defaults: size=%d time=%d", gv.SizeLimit, gv.TimeLimitSeconds)
	}
	over := validInput("Capped over")
	over.SizeLimit = ip(101)
	if _, err := g.svc.Create(ctx, a, crudTenantA, over); !errors.Is(err, ErrValidation) {
		t.Fatalf("size above deployment max: %v", err)
	}
	over = validInput("Capped over")
	over.TimeLimitSeconds = ip(11)
	if _, err := g.svc.Create(ctx, a, crudTenantA, over); !errors.Is(err, ErrValidation) {
		t.Fatalf("time above deployment max: %v", err)
	}

	// Clearing the CA with "" returns to system roots; a trust change needs
	// the bind password again (T070).
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{CAPEM: sp("")}); !errors.Is(err, ErrValidation) {
		t.Fatalf("clear ca without password: %v", err)
	}
	cleared, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{CAPEM: sp(""), BindPassword: sp(crudPW2)})
	if err != nil || cleared.CAPEMSet || f.row(t, crudTenantA, v.ID).CAPEM != "" {
		t.Fatalf("clear ca: %v", err)
	}
	// StartTLS over ldap:// on the global catalog port is accepted.
	st := validInput("Corp GC")
	st.URL, st.TLSMode = sp("ldap://gc.corp.example:3268"), sp("starttls")
	if _, err := f.svc.Create(ctx, a, crudTenantA, st); err != nil {
		t.Fatalf("starttls: %v", err)
	}
}

func TestKindPresets(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)

	ad := f.create(t, crudTenantA, validInput("AD"))
	if want := (Mapping{UID: "objectGUID", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"}); ad.Attributes != want {
		t.Fatalf("active_directory preset %+v, want %+v", ad.Attributes, want)
	}
	if r := f.row(t, crudTenantA, ad.ID); r.AttrUID != "objectGUID" || r.AttrEmail != "mail" || r.AttrDisplayName != "displayName" || r.AttrFirstName != "givenName" || r.AttrLastName != "sn" {
		t.Fatalf("stored mapping %+v", r)
	}

	ol := validInput("OpenLDAP")
	ol.Kind = sp("openldap")
	olv := f.create(t, crudTenantA, ol)
	m := olv.Attributes
	if m.UID != "entryUUID" || m.Email != "mail" || m.FirstName != "givenName" || m.LastName != "sn" || (m.DisplayName != "cn" && m.DisplayName != "displayName") {
		t.Fatalf("openldap preset %+v", m)
	}

	// Explicit attributes win; empty ones are filled from the preset.
	part := validInput("AD custom")
	part.Attributes = &Mapping{Email: "userPrincipalName", DisplayName: "cn"}
	pv := f.create(t, crudTenantA, part)
	if want := (Mapping{UID: "objectGUID", Email: "userPrincipalName", DisplayName: "cn", FirstName: "givenName", LastName: "sn"}); pv.Attributes != want {
		t.Fatalf("partial mapping %+v, want %+v", pv.Attributes, want)
	}

	// "other" has no unique-id preset: the uid attribute must be given.
	other := validInput("Other")
	other.Kind = sp("other")
	if _, err := f.svc.Create(ctx, a, crudTenantA, other); !errors.Is(err, ErrValidation) {
		t.Fatalf("other without uid attribute: %v", err)
	}
	other.Attributes = &Mapping{UID: "uid", DisplayName: "cn"}
	ov := f.create(t, crudTenantA, other)
	if ov.Attributes.UID != "uid" || ov.Attributes.Email != "mail" || ov.Attributes.DisplayName != "cn" {
		t.Fatalf("other mapping %+v", ov.Attributes)
	}
}

func TestDuplicateName(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	f.create(t, crudTenantA, validInput("Corp AD"))
	if _, err := f.svc.Create(ctx, a, crudTenantA, validInput("corp ad")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("case-insensitive duplicate: %v", err)
	}
	// The same name in another tenant is fine.
	f.create(t, crudTenantB, validInput("Corp AD"))
	// Renaming onto an existing name is a duplicate too.
	second := f.create(t, crudTenantA, validInput("Second"))
	if _, err := f.svc.Update(ctx, a, crudTenantA, second.ID, Input{Name: sp("CORP AD")}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("rename duplicate: %v", err)
	}
	// Keeping one's own name (different case) is not.
	if _, err := f.svc.Update(ctx, a, crudTenantA, second.ID, Input{Name: sp("SECOND")}); err != nil {
		t.Fatalf("self rename: %v", err)
	}
}

func TestConnectionCap(t *testing.T) {
	f := newCRUD(t, crudMaxConns(2))
	ctx := context.Background()
	a := actorOf(crudTenantA)
	first := f.create(t, crudTenantA, validInput("One"))
	f.create(t, crudTenantA, validInput("Two"))
	if _, err := f.svc.Create(ctx, a, crudTenantA, validInput("Three")); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("third connection: %v", err)
	}
	if n, _ := f.ms.CountDirectoryConnections(ctx, crudTenantA); n != 2 {
		t.Fatalf("cap exceeded: %d", n)
	}
	// The cap is per tenant.
	f.create(t, crudTenantB, validInput("One"))
	// Updates are not creates.
	if _, err := f.svc.Update(ctx, a, crudTenantA, first.ID, Input{Name: sp("One (renamed)")}); err != nil {
		t.Fatalf("update at cap: %v", err)
	}
	// Removing frees a slot.
	if err := f.svc.Remove(ctx, a, crudTenantA, first.ID); err != nil {
		t.Fatal(err)
	}
	f.create(t, crudTenantA, validInput("Three"))
}

func TestRemoveKeepsImportedUsers(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	v := f.create(t, crudTenantA, validInput("Corp AD"))
	keep := f.create(t, crudTenantA, validInput("Other AD"))
	uid, uid2 := store.NewID(), store.NewID()
	f.ms.AddUser(store.User{ID: uid, TenantID: crudTenantA, Email: "ana@corp.example", Status: "imported", DisplayName: "Ana"})
	f.ms.AddUser(store.User{ID: uid2, TenantID: crudTenantA, Email: "bo@corp.example", Status: "imported", DisplayName: "Bo"})
	now := time.Now()
	for _, l := range []store.DirectoryLink{
		{UserID: uid, TenantID: crudTenantA, ConnectionID: &v.ID, ConnectionName: "Corp AD", DirectoryUID: "guid-ana", DirectoryDN: "cn=Ana,ou=People,dc=corp,dc=example", FirstImportedAt: now, LastImportedAt: now},
		{UserID: uid2, TenantID: crudTenantA, ConnectionID: &keep.ID, ConnectionName: "Other AD", DirectoryUID: "guid-bo", DirectoryDN: "cn=Bo,dc=corp,dc=example", FirstImportedAt: now, LastImportedAt: now},
	} {
		if err := f.ms.UpsertLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	if err := f.svc.Remove(ctx, a, crudTenantA, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, a, crudTenantA, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed connection still readable: %v", err)
	}
	if err := f.svc.Remove(ctx, a, crudTenantA, v.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	users, err := f.ms.ListUsers(ctx, crudTenantA, "", "imported", 10)
	if err != nil || len(users) != 2 {
		t.Fatalf("imported users must stay: %d %v", len(users), err)
	}
	for _, u := range users {
		if u.Directory == nil {
			t.Fatalf("user %s lost its directory link", u.ID)
		}
		switch u.ID {
		case uid:
			if u.Directory.ConnectionID != nil || u.Directory.ConnectionName != "Corp AD" || u.Directory.DirectoryUID != "guid-ana" || u.Status != "imported" {
				t.Fatalf("link after remove: conn=%v name=%q", u.Directory.ConnectionID, u.Directory.ConnectionName)
			}
		case uid2:
			if u.Directory.ConnectionID == nil || *u.Directory.ConnectionID != keep.ID {
				t.Fatal("links of other connections must be untouched")
			}
		}
	}
}

func TestAuditEvents(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	in := validInput("Corp AD")
	in.CAPEM = sp(testCAPEM(t))
	v := f.create(t, crudTenantA, in)
	ct1 := f.row(t, crudTenantA, v.ID).BindPasswordEnc
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{BindPassword: sp(crudPW2), BaseFilter: sp("(objectClass=person)")}); err != nil {
		t.Fatal(err)
	}
	ct2 := f.row(t, crudTenantA, v.ID).BindPasswordEnc
	if err := f.svc.Remove(ctx, a, crudTenantA, v.ID); err != nil {
		t.Fatal(err)
	}
	// A refused create is audited as refused (policy refusal, D14).
	bad := validInput("Loopback")
	bad.URL = sp("ldaps://127.0.0.1:636")
	if _, err := f.svc.Create(ctx, a, crudTenantA, bad); !errors.Is(err, ldapdir.ErrTargetRefused) {
		t.Fatal(err)
	}

	rows := f.auditRows(t)
	seen := map[string]store.AuditRow{}
	var refusedTarget bool
	for _, r := range rows {
		assertNoSecret(t, "audit "+r.EventType+" details", string(r.Details), ct1, ct2)
		if strings.Contains(string(r.Details), "-----BEGIN") {
			t.Errorf("audit %s details carry the CA PEM", r.EventType)
		}
		var d map[string]any
		if err := json.Unmarshal(r.Details, &d); err != nil {
			t.Fatal(err)
		}
		for k := range d {
			if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "secret") {
				t.Errorf("audit %s has detail key %q", r.EventType, k)
			}
		}
		if r.Outcome == "ok" {
			seen[r.EventType] = r
		}
		if r.EventType == string(audit.DirectoryConnectionCreated) && r.Outcome == "refused" && r.Reason == "target_refused" {
			refusedTarget = true
		}
		capture(t, r)
	}
	for _, et := range []audit.EventType{audit.DirectoryConnectionCreated, audit.DirectoryConnectionUpdated, audit.DirectoryConnectionDeleted} {
		r, ok := seen[string(et)]
		if !ok {
			t.Errorf("no ok %s event", et)
			continue
		}
		if r.TenantID != crudTenantA || r.ActorKind != "user" || r.ActorUserID == nil || *r.ActorUserID != a.UserID || r.SubjectKind != "directory_connection" || r.SubjectID == nil || *r.SubjectID != v.ID {
			t.Errorf("%s: tenant=%s actor=%v subject=%s/%v", et, r.TenantID, r.ActorUserID, r.SubjectKind, r.SubjectID)
		}
	}
	if !refusedTarget {
		t.Error("target_refused create must be audited as refused")
	}
}

func TestCrossTenantIDs(t *testing.T) {
	f := newCRUD(t)
	ctx := context.Background()
	a := actorOf(crudTenantA)
	foreign := f.create(t, crudTenantB, validInput("Globex AD"))
	before := f.row(t, crudTenantB, foreign.ID)

	if _, err := f.svc.Get(ctx, a, crudTenantA, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	if _, err := f.svc.Update(ctx, a, crudTenantA, foreign.ID, Input{Name: sp("hijacked"), BindPassword: sp(crudPW2)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update: %v", err)
	}
	if err := f.svc.Remove(ctx, a, crudTenantA, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove: %v", err)
	}
	if after := f.row(t, crudTenantB, foreign.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("foreign connection was changed")
	}
	if list, _ := f.svc.List(ctx, a, crudTenantA); len(list) != 0 {
		t.Fatal("foreign connection listed")
	}

	// A plain unknown id is not found without a cross-tenant event.
	if _, err := f.svc.Get(ctx, a, crudTenantA, store.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := f.svc.Get(ctx, a, crudTenantA, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}

	var cross int
	for _, r := range f.auditRows(t) {
		if r.EventType != string(audit.CrossTenantRefused) {
			continue
		}
		cross++
		if r.TenantID != crudTenantA || r.Outcome != "refused" || r.SubjectID == nil || *r.SubjectID != foreign.ID || r.ActorUserID == nil || *r.ActorUserID != a.UserID {
			t.Errorf("cross_tenant_refused row: tenant=%s outcome=%s subject=%v", r.TenantID, r.Outcome, r.SubjectID)
		}
		assertNoSecret(t, "cross-tenant audit", string(r.Details), before.BindPasswordEnc)
	}
	if cross != 3 {
		t.Fatalf("want one cross_tenant_refused per foreign-id call (3), got %d", cross)
	}
}
