package invite

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func setup(t *testing.T) (*Service, *memstore.Store, *authz.Fake, *email.Outbox) {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte(`{"password_min_length":10}`)})
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tid, Slug: "owner", Builtin: true})
	ms.AddRole(store.Role{ID: "r-auditor", TenantID: tid, Slug: "auditor"})
	h, _ := crypto.HashPassword("existing-password-1", crypto.DefaultParams)
	ms.AddUser(store.User{ID: "u-exists", TenantID: tid, Email: "exists@x.test", Status: "active", PasswordHash: &h})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{6}, 32))
	sender := &recorder{}
	ob := email.NewOutbox(env, sender, nil, 3, nil)
	fga := authz.NewFake()
	svc := New(ms, ob, authz.New(fga, cache.New(cache.NewMemory()), nil), nil, "https://auth.example.org")
	return svc, ms, fga, ob
}

type recorder struct{ msgs []email.Message }

func (r *recorder) Send(_ context.Context, m email.Message) error {
	r.msgs = append(r.msgs, m)
	return nil
}

func tokenFrom(t *testing.T, ob *email.Outbox, it store.OutboxItem) string {
	t.Helper()
	p, err := ob.Decode(it.ToEmail, it.PayloadEnc)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(p.Text, "token=")
	return strings.TrimSpace(p.Text[i+6:])
}

func TestCreateResendAccept(t *testing.T) {
	svc, ms, fga, ob := setup(t)
	ctx := context.Background()
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid}
	id, err := svc.Create(ctx, admin, tid, " New.Person@X.test ", []string{"r-auditor"})
	if err != nil || id == "" || len(ms.Outbox) != 1 || ms.Outbox[0].ToEmail != "new.person@x.test" {
		t.Fatalf("%q %v outbox=%d", id, err, len(ms.Outbox))
	}
	inv := ms.Invitations[id]
	tok := tokenFrom(t, ob, ms.Outbox[0])
	if inv.TokenHash == tok || inv.TokenHash != crypto.HashToken(tok) || time.Until(inv.ExpiresAt) > Lifetime+time.Minute {
		t.Fatal("token must be stored hashed with a 72 h expiry")
	}
	// Existing active account: same outcome, nothing queued, no new invitation.
	id2, err := svc.Create(ctx, admin, tid, "exists@x.test", nil)
	if err != nil || id2 != "" || len(ms.Outbox) != 1 || len(ms.Invitations) != 1 {
		t.Fatalf("existing account leaked: %q %v", id2, err)
	}
	for _, bad := range []string{"", "no-at", "a@", "@x", "a b@x.test"} {
		if _, err := svc.Create(ctx, admin, tid, bad, nil); !errors.Is(err, ErrBadEmail) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := svc.Create(ctx, admin, tid, "b@x.test", []string{"r-nope"}); err == nil {
		t.Fatal("unknown role accepted")
	}
	// Resend rotates the token: the old one no longer works.
	if err := svc.Resend(ctx, admin, tid, id); err != nil || len(ms.Outbox) != 2 {
		t.Fatal(err)
	}
	if _, err := svc.Accept(ctx, tok, "New Person", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("rotated token accepted")
	}
	tok = tokenFrom(t, ob, ms.Outbox[1])
	if _, err := svc.Accept(ctx, tok, "New Person", "short"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("policy: %v", err)
	}
	acc, err := svc.Accept(ctx, tok, "New Person", "long-enough-password")
	if err != nil || acc.User.Status != "active" || acc.User.Email != "new.person@x.test" || acc.Roles[0] != "auditor" || acc.Tenant.ID != tid {
		t.Fatalf("%+v %v", acc, err)
	}
	if roles, _ := ms.Roles(ctx, tid, acc.User.ID); len(roles) != 1 || roles[0] != "auditor" {
		t.Fatalf("bindings %v", roles)
	}
	if ok, _ := fga.Check(ctx, authz.RoleAssignmentTuple(tid, "auditor", acc.User.ID)); !ok {
		t.Fatal("assignee tuple missing")
	}
	if ok, _ := fga.Check(ctx, authz.MembershipTuple(tid, acc.User.ID, "member")); !ok {
		t.Fatal("member tuple missing")
	}
	// Single use, and resend after acceptance is refused.
	if _, err := svc.Accept(ctx, tok, "Again", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("token reused")
	}
	if err := svc.Resend(ctx, admin, tid, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("resend after accept")
	}
	if _, err := svc.Accept(ctx, "", "x", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("empty token")
	}
}

func TestAcceptExpiryAndInvitedUser(t *testing.T) {
	svc, ms, fga, ob := setup(t)
	ctx := context.Background()
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid}
	// An account pre-created in "invited" state (e.g. by an operator) is activated in place.
	ms.AddUser(store.User{ID: "u-inv", TenantID: tid, Email: "pending@x.test", Status: "invited"})
	id, _ := svc.Create(ctx, admin, tid, "pending@x.test", []string{"r-owner"})
	tok := tokenFrom(t, ob, ms.Outbox[len(ms.Outbox)-1])
	acc, err := svc.Accept(ctx, tok, "Pending", "long-enough-password")
	if err != nil || acc.User.ID != "u-inv" || acc.User.Status != "active" || acc.User.PasswordHash == nil {
		t.Fatalf("%+v %v", acc, err)
	}
	if ok, _ := fga.Check(ctx, authz.MembershipTuple(tid, "u-inv", "owner")); !ok {
		t.Fatal("owner tuple missing")
	}
	_ = id
	// Expired tokens are refused.
	id2, _ := svc.Create(ctx, admin, tid, "late@x.test", nil)
	tok2 := tokenFrom(t, ob, ms.Outbox[len(ms.Outbox)-1])
	svc.now = func() time.Time { return time.Now().Add(Lifetime + time.Minute) }
	if _, err := svc.Accept(ctx, tok2, "Late", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("expired token accepted")
	}
	_ = id2
	// Suspended tenant blocks acceptance.
	svc.now = time.Now
	id3, _ := svc.Create(ctx, admin, tid, "frozen@x.test", nil)
	tok3 := tokenFrom(t, ob, ms.Outbox[len(ms.Outbox)-1])
	tn := ms.Tenants[tid]
	tn.Status = "suspended"
	ms.AddTenant(tn)
	if _, err := svc.Accept(ctx, tok3, "F", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("suspended tenant accepted")
	}
	_ = id3
}

// TestInviteIntoGroups (feature 004): an invitation may name groups and
// first/last names; acceptance joins the groups that still exist and fills
// the profile; missing groups are skipped and recorded.
func TestInviteIntoGroups(t *testing.T) {
	svc, ms, fga, ob := setup(t)
	ctx := context.Background()
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid, Roles: []string{"admin"}}
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	svc.audit = aw
	_ = ms.CreateGroup(ctx, store.Group{ID: "g-fin", TenantID: tid, Name: "Finance"})
	_ = ms.CreateGroup(ctx, store.Group{ID: "g-tmp", TenantID: tid, Name: "Temporary"})
	_ = ms.ReplaceGroupRoles(ctx, tid, "g-fin", "", []string{"r-auditor"})
	// Unknown or foreign group ids and bad names are refused at creation.
	if _, err := svc.CreateWith(ctx, admin, tid, Params{Email: "a@x.test", GroupIDs: []string{"g-nope"}}); !errors.Is(err, ErrBadEmail) {
		t.Fatalf("unknown group: %v", err)
	}
	if _, err := svc.CreateWith(ctx, admin, tid, Params{Email: "a@x.test", FirstName: strings.Repeat("x", 101)}); !errors.Is(err, ErrBadEmail) {
		t.Fatalf("long name: %v", err)
	}
	id, err := svc.CreateWith(ctx, admin, tid, Params{Email: "dana@x.test", RoleIDs: nil, GroupIDs: []string{"g-fin", "g-tmp"}, FirstName: " Dana ", LastName: "Kovač"})
	if err != nil || id == "" {
		t.Fatal(err)
	}
	if inv := ms.Invitations[id]; len(inv.GroupIDs) != 2 || inv.FirstName != "Dana" {
		t.Fatalf("stored %+v", inv)
	}
	// The temporary group disappears before acceptance.
	_ = ms.DeleteGroup(ctx, tid, "g-tmp")
	tok := tokenFrom(t, ob, ms.Outbox[len(ms.Outbox)-1])
	acc, err := svc.Accept(ctx, tok, "", "long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if acc.User.FirstName != "Dana" || acc.User.LastName != "Kovač" || acc.User.DisplayName != "Dana Kovač" {
		t.Fatalf("profile from the invitation: %+v", acc.User)
	}
	if ok, _ := ms.IsGroupMember(ctx, tid, "g-fin", acc.User.ID); !ok {
		t.Fatal("must join the existing group")
	}
	if ok, _ := fga.Check(ctx, authz.GroupMembershipTuple(tid, "g-fin", acc.User.ID)); !ok {
		t.Fatal("group membership tuple missing")
	}
	if roles, _ := ms.Roles(ctx, tid, acc.User.ID); len(roles) != 1 || roles[0] != "auditor" {
		t.Fatalf("effective roles through the group: %v", roles)
	}
	aw.Flush()
	found := false
	for _, r := range ms.AuditRows {
		if r.EventType == string(audit.InviteAccepted) && strings.Contains(string(r.Details), `"skipped_groups":["g-tmp"]`) {
			found = true
		}
	}
	if !found {
		t.Fatal("skipped groups must be recorded in the acceptance audit event")
	}
	// An explicit display name given at acceptance still wins.
	id2, _ := svc.CreateWith(ctx, admin, tid, Params{Email: "bob@x.test", FirstName: "Bob", LastName: "K"})
	_ = id2
	tok2 := tokenFrom(t, ob, ms.Outbox[len(ms.Outbox)-1])
	acc2, err := svc.Accept(ctx, tok2, "Bobby", "long-enough-password")
	if err != nil || acc2.User.DisplayName != "Bobby" || acc2.User.FirstName != "Bob" {
		t.Fatalf("%+v %v", acc2.User, err)
	}
}
