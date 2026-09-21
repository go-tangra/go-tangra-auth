package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const tidP = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func TestNormalizePhone(t *testing.T) {
	good := map[string]string{
		"+385911234567":      "+385911234567",
		"+1 (415) 555-0100":  "+14155550100",
		" +44 20.7946.0958 ": "+442079460958",
		"":                   "",
		"   ":                "",
	}
	for in, want := range good {
		got, err := NormalizePhone(in)
		if err != nil || got != want {
			t.Errorf("%q → %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"0044 20 7946 0958", "+0123456789", "+1234", "+38591123456789012", "+385 91 abc", "911234567", "+385\u200b911234567"} {
		if _, err := NormalizePhone(bad); !errors.Is(err, ErrInvalidPhone) {
			t.Errorf("%q accepted (%v)", bad, err)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"Dana", "  Kovač ", "O'Brien", "Jean-Luc", "李", "Zoë", ""} {
		if _, err := ValidateName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	if got, _ := ValidateName("  Kovač "); got != "Kovač" {
		t.Errorf("trim: %q", got)
	}
	for _, bad := range []string{strings.Repeat("x", 101), "a\x00b", "a\nb", "tab\there"} {
		if _, err := ValidateName(bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestProfileUpdateAndDisplayName(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tidP, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tidP, Email: "dana@x.test", DisplayName: "dana@x.test", Status: "active", DisplayNameExplicit: false})
	ms.AddUser(store.User{ID: "u2", TenantID: tidP, Email: "bob@x.test", DisplayName: "Bobby", Status: "active", DisplayNameExplicit: true})
	ms.AddUser(store.User{ID: "u9", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Email: "f@x.test", Status: "active"})
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	p := NewProfiles(ms, aw)
	self := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tidP, Roles: []string{"member"}}
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tidP, Roles: []string{"admin"}}

	// Names derive the display name when it was never set explicitly.
	got, err := p.Update(ctx, self, "u1", ProfileUpdate{FirstName: " Dana ", LastName: "Kovač", Phone: "+385 91 123 4567"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Dana Kovač" || got.FirstName != "Dana" || got.Phone != "+385911234567" {
		t.Fatalf("%+v", got)
	}
	// An explicit display name sticks; empty names fall back to it, then to the email local part.
	if got, err = p.Update(ctx, admin, "u2", ProfileUpdate{FirstName: "Bob", LastName: "K"}); err != nil || got.DisplayName != "Bobby" {
		t.Fatalf("explicit display name must be kept: %+v %v", got, err)
	}
	dn := "Robert"
	if got, err = p.Update(ctx, self, "u1", ProfileUpdate{FirstName: "Dana", LastName: "Kovač", DisplayName: &dn}); err != nil || got.DisplayName != "Robert" {
		t.Fatalf("%+v %v", got, err)
	}
	empty := ""
	if got, err = p.Update(ctx, self, "u1", ProfileUpdate{DisplayName: &empty}); err != nil || got.DisplayName != "dana" {
		t.Fatalf("empty everything falls back to the email local part: %+v %v", got, err)
	}
	// Validation.
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{Phone: "12345"}); !errors.Is(err, ErrInvalidPhone) {
		t.Fatalf("phone: %v", err)
	}
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{FirstName: strings.Repeat("x", 101)}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("name: %v", err)
	}
	// Authorization: a member cannot edit someone else; admins can; cross-tenant is not found.
	if _, err := p.Update(ctx, self, "u2", ProfileUpdate{FirstName: "X"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member editing another: %v", err)
	}
	if _, err := p.Update(ctx, admin, "u1", ProfileUpdate{FirstName: "Dana", LastName: "K"}); err != nil {
		t.Fatalf("admin edit: %v", err)
	}
	if _, err := p.Update(ctx, admin, "u9", ProfileUpdate{FirstName: "X"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if _, err := p.Get(ctx, admin, "u9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	// Public lookup never carries the phone and omits foreign ids.
	pubs, err := p.Lookup(ctx, self, []string{"u1", "u2", "u9"})
	if err != nil || len(pubs) != 2 {
		t.Fatalf("%v %v", pubs, err)
	}
	// Audit: field names only, never values.
	aw.Flush()
	seen := 0
	for _, r := range ms.AuditRows {
		if r.EventType != string(audit.ProfileUpdated) || r.Outcome != "ok" {
			continue
		}
		seen++
		js := string(r.Details)
		if strings.Contains(js, "+385") || strings.Contains(js, "Kovač") || !strings.Contains(js, `"fields"`) {
			t.Fatalf("audit details leak or lack field names: %s", js)
		}
		if r.SubjectKind != "user" {
			t.Fatalf("subject %+v", r)
		}
	}
	if seen == 0 {
		t.Fatal("profile updates must be audited")
	}
}

func TestProfileSearch(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddUser(store.User{ID: "u1", TenantID: tidP, Email: "dana@x.test", DisplayName: "Dana Kovač", FirstName: "Dana", LastName: "Kovač", Phone: "+385911234567", Status: "active"})
	ms.AddUser(store.User{ID: "u2", TenantID: tidP, Email: "bob@x.test", DisplayName: "Bobby", Status: "active"})
	ms.AddUser(store.User{ID: "u3", TenantID: tidP, Email: "gone@x.test", DisplayName: "Dana Gone", Status: "deactivated"})
	ms.AddUser(store.User{ID: "u9", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Email: "dana@other.test", DisplayName: "Dana", Status: "active"})
	for i := 0; i < SearchMax+5; i++ {
		ms.AddUser(store.User{ID: "m" + strings.Repeat("0", 2) + string(rune('a'+i)), TenantID: tidP, Email: "many" + string(rune('a'+i)) + "@x.test", DisplayName: "Many", Status: "active"})
	}
	p := NewProfiles(ms, nil)
	self := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tidP}
	if _, err := p.Search(ctx, self, " d "); !errors.Is(err, ErrQueryTooShort) {
		t.Fatalf("short: %v", err)
	}
	out, err := p.Search(ctx, self, "KOVA")
	if err != nil || len(out) != 1 || out[0].ID != "u1" || out[0].Email != "dana@x.test" {
		t.Fatalf("%v %+v", err, out)
	}
	// Name match excludes deactivated and foreign members; email is present, phone never.
	out, _ = p.Search(ctx, self, "dana")
	if len(out) != 1 || out[0].ID != "u1" {
		t.Fatalf("%+v", out)
	}
	if out, _ = p.Search(ctx, self, "many"); len(out) != SearchMax {
		t.Fatalf("cap: %d", len(out))
	}
	if out, _ = p.Search(ctx, self, strings.Repeat("x", 300)); len(out) != 0 {
		t.Fatalf("long: %d", len(out))
	}
	f := &failUserStore{Store: ms, fail: map[string]bool{"search": true}}
	if _, err := NewProfiles(f, nil).Search(ctx, self, "dana"); !errors.Is(err, errDown) {
		t.Fatalf("failure: %v", err)
	}
}
