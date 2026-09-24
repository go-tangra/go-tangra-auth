package directory

// Regression tests for the T070 security review findings (recorded in
// docs/security-model.md, "Security review (T070)").

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/ldapdir"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

const rvPlainID = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"

// refusedWith reports whether rows hold a refused event with reason.
func refusedWith(rows []store.AuditRow, reason string) bool {
	for i := range rows {
		if rows[i].Outcome == "refused" && rows[i].Reason == reason {
			return true
		}
	}
	return false
}

// F1: the stored bind password is never sent to a changed destination or
// trust anchor; the caller must type it again.
func TestReviewStoredPasswordNotReplayedToNewTarget(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(*Input){
		"url": func(in *Input) { in.URL = ttPtr("ldaps://collector.attacker.test:636") },
		"tls_mode": func(in *Input) {
			in.URL, in.TLSMode = ttPtr("ldap://ldap.example.test:389"), ttPtr(ldapdir.TLSModeStartTLS)
		},
		"ca_pem": func(in *Input) { in.CAPEM = ttPtr("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n") },
	} {
		t.Run("test/"+name, func(t *testing.T) {
			f := ttSetup(t, ttOpts{})
			in := ttInput()
			in.BindPassword = nil
			edit(&in)
			if _, err := f.svc.Test(ctx, ttAdmin(ttTenant), ttTenant, in, ttConnID); !errors.Is(err, ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if len(f.dir.Opens()) != 0 || len(f.dir.Binds()) != 0 {
				t.Fatal("a changed target must not be dialled with the stored password")
			}
			if !refusedWith(f.tested(), "bind_password_required") {
				t.Fatal("refusal not audited")
			}
			f.noSecretInAudit(t)
		})
	}

	f := newCRUD(t)
	a := actorOf(crudTenantA)
	v := f.create(t, crudTenantA, validInput("Corp AD"))
	before := f.row(t, crudTenantA, v.ID)
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{URL: sp("ldaps://collector.attacker.test:636")}); !errors.Is(err, ErrValidation) {
		t.Fatalf("update url without password: %v", err)
	}
	if after := f.row(t, crudTenantA, v.ID); after.URL != before.URL {
		t.Fatal("refused update must not be stored")
	}
	if !refusedWith(f.auditRows(t), "bind_password_required") {
		t.Fatal("update refusal not audited")
	}
	// Retyping the password makes the same change legitimate; other fields
	// still keep the stored one.
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{URL: sp("ldaps://dc2.corp.example:636"), BindPassword: sp(crudPW2)}); err != nil {
		t.Fatalf("update url with password: %v", err)
	}
	if _, err := f.svc.Update(ctx, a, crudTenantA, v.ID, Input{Name: sp("Corp AD 2"), BaseDN: sp("dc=corp,dc=example")}); err != nil {
		t.Fatalf("update without target change: %v", err)
	}
}

// F2: an import is one outbound session and shares the per-tenant limit
// with tests and searches.
func TestReviewImportRateLimited(t *testing.T) {
	f := ttSetup(t, ttOpts{rate: 1})
	ctx := context.Background()
	if _, err := f.svc.Import(ctx, ttAdmin(ttTenant), ttTenant, ttConnID, []string{"uid-1"}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	opens := len(f.dir.Opens())
	if _, err := f.svc.Import(ctx, ttAdmin(ttTenant), ttTenant, ttConnID, []string{"uid-1"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if len(f.dir.Opens()) != opens {
		t.Fatal("a rate-limited import must not dial")
	}
	if !refusedWith(f.events(audit.DirectoryImported), ErrRateLimited.Error()) {
		t.Fatal("rate-limited import not audited")
	}
}

// F3: a stored plain connection is refused at use once the deployment no
// longer allows plaintext, before its password is unsealed.
func TestReviewPlaintextRefusedAtUse(t *testing.T) {
	f := ttSetup(t, ttOpts{})
	ctx := context.Background()
	c := f.conn(t, ttTenant, ttConnID)
	c.ID, c.Name, c.URL, c.TLSMode = rvPlainID, "Dev LDAP", "ldap://ldap.example.test:389", ldapdir.TLSModePlain
	if err := f.ms.InsertDirectoryConnection(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Search(ctx, ttAdmin(ttTenant), ttTenant, rvPlainID, SearchRequest{}); !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("search: want ErrInsecureTransport, got %v", err)
	}
	if _, err := f.svc.Import(ctx, ttAdmin(ttTenant), ttTenant, rvPlainID, []string{"uid-1"}); !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("import: want ErrInsecureTransport, got %v", err)
	}
	if _, err := f.svc.TestSaved(ctx, ttAdmin(ttTenant), ttTenant, rvPlainID); !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("test: want ErrInsecureTransport, got %v", err)
	}
	if len(f.dir.Opens()) != 0 {
		t.Fatal("a refused plain connection must not dial")
	}
	if !refusedWith(f.events(audit.DirectorySearched), "insecure_transport") || !refusedWith(f.events(audit.DirectoryImported), "insecure_transport") {
		t.Fatal("plaintext refusals not audited")
	}
}

// F4: a base filter is held to the search filter policy when it is saved.
func TestReviewBaseFilterPolicyAtSave(t *testing.T) {
	f := newCRUD(t)
	for name, filter := range map[string]string{
		"dn matching":   "(cn:dn:=People)",
		"bad attribute": "(1abc=x)",
		"escaped NUL":   `(cn=a\00b)`,
	} {
		in := validInput("Corp " + name)
		in.BaseFilter = sp(filter)
		if _, err := f.svc.Create(context.Background(), actorOf(crudTenantA), crudTenantA, in); !errors.Is(err, ldapdir.ErrInvalidFilter) {
			t.Errorf("%s: want ErrInvalidFilter, got %v", name, err)
		}
	}
	in := validInput("Corp ok")
	in.BaseFilter = sp("(objectClass=person)")
	if v := f.create(t, crudTenantA, in); v.BaseFilter != "(objectClass=person)" {
		t.Fatalf("canonical base filter: %q", v.BaseFilter)
	}
}
