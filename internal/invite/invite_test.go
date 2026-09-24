package invite

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
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

// TestAcceptNeverActivatesImported (feature 016, SR-006): only an "invited"
// row is activated by Accept. An imported row reached by a live token without
// having been moved to "invited" is refused like a bad token and left as is.
func TestAcceptNeverActivatesImported(t *testing.T) {
	svc, ms, fga, _ := setup(t)
	ctx := context.Background()
	ms.AddUser(store.User{ID: "u-imp", TenantID: tid, Email: "imported@x.test", Status: "imported"})
	tok, err := crypto.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	_ = ms.InsertInvitation(ctx, store.Invitation{ID: "inv-imp", TenantID: tid, Email: "imported@x.test", RoleIDs: []string{"r-owner"},
		TokenHash: crypto.HashToken(tok), ExpiresAt: time.Now().Add(Lifetime)})
	if _, err := svc.Accept(ctx, tok, "Imported", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("imported row accepted: %v", err)
	}
	u, err := ms.UserByEmail(ctx, tid, "imported@x.test")
	if err != nil || u.Status != "imported" || u.PasswordHash != nil {
		t.Fatalf("imported row changed: status=%q hash=%v err=%v", u.Status, u.PasswordHash != nil, err)
	}
	if ms.Invitations["inv-imp"].AcceptedAt != nil {
		t.Fatal("invitation marked accepted")
	}
	if roles, _ := ms.Roles(ctx, tid, "u-imp"); len(roles) != 0 {
		t.Fatalf("roles bound: %v", roles)
	}
	if ok, _ := fga.Check(ctx, authz.MembershipTuple(tid, "u-imp", "owner")); ok {
		t.Fatal("membership tuple written")
	}
}

// ---------------------------------------------------------------- feature 016: activation (US3, research D11)

const (
	otherTid   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	foreignUID = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	connID     = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

// fakeEscalation stands in for authz.Assigner.MayAssign: it refuses any
// role or group listed in deny and records every call.
type fakeEscalation struct {
	deny  map[string]bool
	calls []escCall
	// state observed at call time: nothing may be written before the check.
	ms                  *memstore.Store
	invitations, outbox []int
}

type escCall struct {
	actor             tenantctx.Actor
	tenantID          string
	roleIDs, groupIDs []string
}

func (f *fakeEscalation) MayAssign(_ context.Context, actor tenantctx.Actor, tenantID string, roleIDs, groupIDs []string) error {
	f.calls = append(f.calls, escCall{actor: actor, tenantID: tenantID, roleIDs: append([]string(nil), roleIDs...), groupIDs: append([]string(nil), groupIDs...)})
	if f.ms != nil {
		f.invitations = append(f.invitations, len(f.ms.Invitations))
		f.outbox = append(f.outbox, len(f.ms.Outbox))
	}
	for _, id := range append(append([]string(nil), roleIDs...), groupIDs...) {
		if f.deny[id] {
			return authz.ErrSelfEscalation
		}
	}
	return nil
}

// failingStore wraps memstore so one e-mail's invitation insert fails; the
// Tx handed to the service is the wrapper, everything else is promoted.
type failingStore struct {
	*memstore.Store
	failEmail string
}

func (f *failingStore) Atomic(ctx context.Context, sc store.Scope, fn func(any) error) error {
	return f.Store.Atomic(ctx, sc, func(any) error { return fn(f) })
}

func (f *failingStore) InsertInvitation(ctx context.Context, i store.Invitation) error {
	if strings.EqualFold(i.Email, f.failEmail) {
		return errors.New("injected invitation failure")
	}
	return f.Store.InsertInvitation(ctx, i)
}

type actFixture struct {
	svc   *Service
	ms    *memstore.Store
	fga   *authz.Fake
	ob    *email.Outbox
	aw    *audit.Writer
	esc   *fakeEscalation
	admin tenantctx.Actor
}

func actSetup(t *testing.T) *actFixture {
	t.Helper()
	svc, ms, fga, ob := setup(t)
	ctx := context.Background()
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	svc.audit = aw
	esc := &fakeEscalation{deny: map[string]bool{}, ms: ms}
	svc = svc.WithEscalation(esc)
	ms.AddTenant(store.Tenant{ID: otherTid, Slug: "other", Status: "active", Kind: "customer", Policy: []byte(`{}`)})
	_ = ms.CreateGroup(ctx, store.Group{ID: "g-fin", TenantID: tid, Name: "Finance"})
	if err := ms.InsertDirectoryConnection(ctx, store.DirectoryConnection{ID: connID, TenantID: tid, Name: "Corp LDAP", Kind: "openldap", URL: "ldaps://ldap.example.org",
		TLSMode: "ldaps", BaseDN: "dc=example,dc=org", SizeLimit: 100, TimeLimitSeconds: 10}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []store.User{
		{ID: "u-imp1", TenantID: tid, Email: "ana@x.test", Status: "imported", FirstName: "Ana", LastName: "Petrova", DisplayName: "Ana Petrova"},
		{ID: "u-imp2", TenantID: tid, Email: "boris@x.test", Status: "imported", FirstName: "Boris", LastName: "Ivanov", DisplayName: "Boris Ivanov"},
		{ID: "u-imp3", TenantID: tid, Email: "cveta@x.test", Status: "imported", FirstName: "Cveta", LastName: "Koleva", DisplayName: "Cveta Koleva"},
		{ID: "u-inv", TenantID: tid, Email: "pending@x.test", Status: "invited"},
		{ID: "u-off", TenantID: tid, Email: "off@x.test", Status: "deactivated"},
		{ID: foreignUID, TenantID: otherTid, Email: "foreign@x.test", Status: "imported"},
	} {
		ms.AddUser(u)
		if u.Status == "imported" && u.TenantID == tid {
			cid := connID
			if err := ms.UpsertLink(ctx, store.DirectoryLink{UserID: u.ID, TenantID: tid, ConnectionID: &cid, ConnectionName: "Corp LDAP",
				DirectoryUID: "uid-" + u.ID, DirectoryDN: "uid=" + u.ID + ",dc=example,dc=org", FirstImportedAt: time.Now(), LastImportedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid, Roles: []string{"admin"}}
	return &actFixture{svc: svc, ms: ms, fga: fga, ob: ob, aw: aw, esc: esc, admin: admin}
}

func (f *actFixture) status(t *testing.T, uid string) string {
	t.Helper()
	u, err := f.ms.User(context.Background(), tid, uid)
	if err != nil {
		t.Fatalf("user %s: %v", uid, err)
	}
	return u.Status
}

func (f *actFixture) auditRows(eventType string) []store.AuditRow {
	f.aw.Flush()
	var out []store.AuditRow
	for _, r := range f.ms.AuditRows {
		if r.EventType == eventType {
			out = append(out, r)
		}
	}
	return out
}

func (f *actFixture) outboxFor(addr string) []store.OutboxItem {
	var out []store.OutboxItem
	for _, it := range f.ms.Outbox {
		if it.ToEmail == addr {
			out = append(out, it)
		}
	}
	return out
}

func itemFor(t *testing.T, items []ActivateItem, uid string) ActivateItem {
	t.Helper()
	for _, it := range items {
		if it.UserID == uid {
			return it
		}
	}
	t.Fatalf("no result item for %s in %+v", uid, items)
	return ActivateItem{}
}

// TestActivateImported: imported → invited with an invitation (names from the
// user row, roles, groups, 72 h) and an "invite" outbox row, audited as
// invite_created with reason "activation".
func TestActivateImported(t *testing.T) {
	f := actSetup(t)
	ctx := context.Background()
	items, err := f.svc.Activate(ctx, f.admin, tid, []string{"u-imp1"}, Params{RoleIDs: []string{"r-auditor"}, GroupIDs: []string{"g-fin"}})
	if err != nil || len(items) != 1 {
		t.Fatalf("%+v %v", items, err)
	}
	it := items[0]
	if it.UserID != "u-imp1" || it.Outcome != OutcomeInvited || it.Reason != "" || it.InvitationID == "" {
		t.Fatalf("item %+v", it)
	}
	if got := f.status(t, "u-imp1"); got != "invited" {
		t.Fatalf("status %q, want invited", got)
	}
	inv, ok := f.ms.Invitations[it.InvitationID]
	if !ok {
		t.Fatal("invitation not stored under the returned id")
	}
	if inv.TenantID != tid || inv.Email != "ana@x.test" || inv.FirstName != "Ana" || inv.LastName != "Petrova" {
		t.Fatalf("invitation %+v", inv)
	}
	if len(inv.RoleIDs) != 1 || inv.RoleIDs[0] != "r-auditor" || len(inv.GroupIDs) != 1 || inv.GroupIDs[0] != "g-fin" {
		t.Fatalf("roles/groups %v %v", inv.RoleIDs, inv.GroupIDs)
	}
	if inv.InvitedBy == nil || *inv.InvitedBy != "u-admin" {
		t.Fatal("invited_by must be the actor")
	}
	if left := time.Until(inv.ExpiresAt); left > Lifetime+time.Minute || left < Lifetime-time.Minute {
		t.Fatalf("expiry %v, want 72 h", left)
	}
	ob := f.outboxFor("ana@x.test")
	if len(ob) != 1 || ob[0].Kind != "invite" || ob[0].TenantID != tid {
		t.Fatalf("outbox %+v", ob)
	}
	if tok := tokenFrom(t, f.ob, ob[0]); inv.TokenHash != crypto.HashToken(tok) || inv.TokenHash == tok {
		t.Fatal("the mailed token must match the stored hash")
	}
	// Escalation was checked with the requested roles and groups.
	if len(f.esc.calls) != 1 || f.esc.calls[0].tenantID != tid || f.esc.calls[0].actor.UserID != "u-admin" ||
		len(f.esc.calls[0].roleIDs) != 1 || f.esc.calls[0].roleIDs[0] != "r-auditor" || len(f.esc.calls[0].groupIDs) != 1 || f.esc.calls[0].groupIDs[0] != "g-fin" {
		t.Fatalf("escalation calls %+v", f.esc.calls)
	}
	rows := f.auditRows(string(audit.InviteCreated))
	if len(rows) != 1 {
		t.Fatalf("invite_created rows %d", len(rows))
	}
	r := rows[0]
	if r.Outcome != "ok" || r.Reason != "activation" || r.SubjectKind != "user" || r.SubjectID == nil || *r.SubjectID != "u-imp1" ||
		r.ActorUserID == nil || *r.ActorUserID != "u-admin" || !strings.Contains(string(r.Details), `"invitation_id":"`+it.InvitationID+`"`) {
		t.Fatalf("audit %+v details=%s", r, r.Details)
	}
	if strings.Contains(string(r.Details), "ana@x.test") || strings.Contains(string(r.Details), "Petrova") {
		t.Fatal("audit details must not carry e-mail or names")
	}
	// The link row is untouched.
	if l, _ := f.ms.LinksByUIDs(ctx, tid, connID, []string{"uid-u-imp1"}); len(l) != 1 {
		t.Fatal("link row must stay")
	}
}

// TestActivateRefusals: per-user failures (invalid_state, not_found incl. a
// cross-tenant id) and whole-request refusals (size, escalation).
func TestActivateRefusals(t *testing.T) {
	f := actSetup(t)
	ctx := context.Background()
	items, err := f.svc.Activate(ctx, f.admin, tid, []string{"u-inv", "u-exists", "u-off", foreignUID, "0190f7c2-6a3e-7c1a-9b2e-000000000000"}, Params{})
	if err != nil || len(items) != 5 {
		t.Fatalf("%+v %v", items, err)
	}
	for _, uid := range []string{"u-inv", "u-exists", "u-off"} {
		if it := itemFor(t, items, uid); it.Outcome != OutcomeFailed || it.Reason != ReasonInvalidState || it.InvitationID != "" {
			t.Errorf("%s: %+v, want failed invalid_state", uid, it)
		}
	}
	for _, uid := range []string{foreignUID, "0190f7c2-6a3e-7c1a-9b2e-000000000000"} {
		if it := itemFor(t, items, uid); it.Outcome != OutcomeFailed || it.Reason != ReasonNotFound || it.InvitationID != "" {
			t.Errorf("%s: %+v, want failed not_found", uid, it)
		}
	}
	if f.status(t, "u-inv") != "invited" || f.status(t, "u-exists") != "active" || f.status(t, "u-off") != "deactivated" {
		t.Fatal("non-imported users must not change")
	}
	if fu, _ := f.ms.User(ctx, otherTid, foreignUID); fu.Status != "imported" {
		t.Fatalf("foreign user changed: %q", fu.Status)
	}
	if len(f.ms.Invitations) != 0 || len(f.ms.Outbox) != 0 {
		t.Fatalf("nothing may be written: invitations=%d outbox=%d", len(f.ms.Invitations), len(f.ms.Outbox))
	}
	cross := f.auditRows(string(audit.CrossTenantRefused))
	if len(cross) != 1 || cross[0].TenantID != tid || cross[0].SubjectID == nil || *cross[0].SubjectID != foreignUID || cross[0].Outcome != "refused" {
		t.Fatalf("cross_tenant_refused %+v", cross)
	}
	if strings.Contains(string(cross[0].Details), "foreign@x.test") {
		t.Fatal("cross-tenant audit must not name the foreign e-mail")
	}
	if rows := f.auditRows(string(audit.InviteCreated)); len(rows) != 0 {
		t.Fatalf("no invite_created for failures, got %d", len(rows))
	}

	// Escalation: checked once, before any invitation or outbox row; the
	// whole request is refused and nobody changes.
	f.esc.deny["r-owner"] = true
	f.esc.calls, f.esc.invitations, f.esc.outbox = nil, nil, nil
	items, err = f.svc.Activate(ctx, f.admin, tid, []string{"u-imp1", "u-imp2", "u-imp3"}, Params{RoleIDs: []string{"r-owner"}})
	if !errors.Is(err, authz.ErrSelfEscalation) || items != nil {
		t.Fatalf("escalation: %+v %v", items, err)
	}
	if len(f.esc.calls) != 1 || f.esc.invitations[0] != 0 || f.esc.outbox[0] != 0 {
		t.Fatalf("escalation must be checked once before writing: calls=%d inv=%v outbox=%v", len(f.esc.calls), f.esc.invitations, f.esc.outbox)
	}
	for _, uid := range []string{"u-imp1", "u-imp2", "u-imp3"} {
		if f.status(t, uid) != "imported" {
			t.Fatalf("%s changed after refusal", uid)
		}
	}
	if len(f.ms.Invitations) != 0 || len(f.ms.Outbox) != 0 {
		t.Fatal("escalation refusal wrote rows")
	}
	// A group that grants more than the actor holds is refused the same way.
	delete(f.esc.deny, "r-owner")
	f.esc.deny["g-fin"] = true
	if _, err := f.svc.Activate(ctx, f.admin, tid, []string{"u-imp1"}, Params{GroupIDs: []string{"g-fin"}}); !errors.Is(err, authz.ErrSelfEscalation) {
		t.Fatalf("group escalation: %v", err)
	}
	delete(f.esc.deny, "g-fin")
	if len(f.ms.Invitations) != 0 || len(f.ms.Outbox) != 0 {
		t.Fatal("group escalation refusal wrote rows")
	}

	// Request bounds: 1..ActivateMax unique ids, ≤ GroupsMax groups, roles and
	// groups that exist in the tenant. All refused before any write.
	many := make([]string, ActivateMax+1)
	for i := range many {
		many[i] = store.NewID()
	}
	exact := many[:ActivateMax]
	bad := map[string]struct {
		ids []string
		p   Params
	}{
		"too many ids":  {many, Params{}},
		"no ids":        {nil, Params{}},
		"duplicate ids": {[]string{"u-imp1", "u-imp1"}, Params{}},
		"too many groups": {[]string{"u-imp1"}, Params{GroupIDs: func() []string {
			g := make([]string, GroupsMax+1)
			for i := range g {
				g[i] = "g-fin"
			}
			return g
		}()}},
		"unknown role":  {[]string{"u-imp1"}, Params{RoleIDs: []string{"r-nope"}}},
		"unknown group": {[]string{"u-imp1"}, Params{GroupIDs: []string{"g-nope"}}},
	}
	for name, c := range bad {
		f.esc.calls = nil
		items, err := f.svc.Activate(ctx, f.admin, tid, c.ids, c.p)
		if !errors.Is(err, ErrBadEmail) || items != nil {
			t.Errorf("%s: %+v %v, want validation_failed", name, items, err)
		}
	}
	if f.status(t, "u-imp1") != "imported" || len(f.ms.Invitations) != 0 || len(f.ms.Outbox) != 0 {
		t.Fatal("refused requests wrote rows")
	}
	// Exactly ActivateMax ids is accepted (unknown ids just fail per user).
	items, err = f.svc.Activate(ctx, f.admin, tid, exact, Params{})
	if err != nil || len(items) != ActivateMax {
		t.Fatalf("%d ids: %d items %v", ActivateMax, len(items), err)
	}
}

// TestActivateIsolatesFailures: one user's failure (here the invitation
// insert) leaves the others' invitations intact; the failed user stays
// imported and gets no outbox row.
func TestActivateIsolatesFailures(t *testing.T) {
	f := actSetup(t)
	ctx := context.Background()
	fs := &failingStore{Store: f.ms, failEmail: "boris@x.test"}
	f.svc.st = fs
	items, err := f.svc.Activate(ctx, f.admin, tid, []string{"u-imp1", "u-imp2", "u-exists", "u-imp3"}, Params{RoleIDs: []string{"r-auditor"}})
	if err != nil || len(items) != 4 {
		t.Fatalf("%+v %v", items, err)
	}
	if items[0].UserID != "u-imp1" || items[1].UserID != "u-imp2" || items[2].UserID != "u-exists" || items[3].UserID != "u-imp3" {
		t.Fatalf("items must follow request order: %+v", items)
	}
	for _, uid := range []string{"u-imp1", "u-imp3"} {
		it := itemFor(t, items, uid)
		if it.Outcome != OutcomeInvited || it.InvitationID == "" {
			t.Errorf("%s: %+v", uid, it)
		}
		if f.status(t, uid) != "invited" {
			t.Errorf("%s not invited", uid)
		}
	}
	if it := itemFor(t, items, "u-imp2"); it.Outcome != OutcomeFailed || it.Reason != ReasonInternal || it.InvitationID != "" {
		t.Errorf("u-imp2: %+v, want failed internal", it)
	}
	if it := itemFor(t, items, "u-exists"); it.Outcome != OutcomeFailed || it.Reason != ReasonInvalidState {
		t.Errorf("u-exists: %+v", it)
	}
	if f.status(t, "u-imp2") != "imported" || len(f.outboxFor("boris@x.test")) != 0 {
		t.Fatal("the failed user must stay imported with no e-mail queued")
	}
	if len(f.outboxFor("ana@x.test")) != 1 || len(f.outboxFor("cveta@x.test")) != 1 || len(f.ms.Invitations) != 2 {
		t.Fatalf("others: outbox=%d invitations=%d", len(f.ms.Outbox), len(f.ms.Invitations))
	}
	n := 0
	for _, r := range f.auditRows(string(audit.InviteCreated)) {
		if r.Reason == "activation" && r.Outcome == "ok" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("activation audit rows %d, want 2", n)
	}
}

// TestCreateWithImportedConverts (research D10/D11): a plain invitation to an
// imported user's e-mail activates that user — no second user row, same
// result shape as any other invitation — and plain invitations now pass the
// escalation check.
func TestCreateWithImportedConverts(t *testing.T) {
	f := actSetup(t)
	ctx := context.Background()
	id, err := f.svc.CreateWith(ctx, f.admin, tid, Params{Email: " Ana@X.test ", RoleIDs: []string{"r-auditor"}, GroupIDs: []string{"g-fin"}})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	if f.status(t, "u-imp1") != "invited" {
		t.Fatal("imported user must become invited")
	}
	n := 0
	for _, u := range f.ms.Users {
		if u.TenantID == tid && strings.EqualFold(u.Email, "ana@x.test") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("user rows for the e-mail: %d", n)
	}
	inv := f.ms.Invitations[id]
	if inv.Email != "ana@x.test" || len(inv.RoleIDs) != 1 || inv.RoleIDs[0] != "r-auditor" || len(inv.GroupIDs) != 1 {
		t.Fatalf("invitation %+v", inv)
	}
	if ob := f.outboxFor("ana@x.test"); len(ob) != 1 || ob[0].Kind != "invite" {
		t.Fatalf("outbox %+v", ob)
	}
	rows := f.auditRows(string(audit.InviteCreated))
	if len(rows) != 1 || rows[0].Outcome != "ok" || rows[0].Reason != "activation" || rows[0].SubjectID == nil || *rows[0].SubjectID != "u-imp1" {
		t.Fatalf("audit %+v", rows)
	}
	if len(f.esc.calls) != 1 || f.esc.calls[0].roleIDs[0] != "r-auditor" || f.esc.calls[0].groupIDs[0] != "g-fin" {
		t.Fatalf("escalation calls %+v", f.esc.calls)
	}
	// Same result shape as a brand-new address: an id and no error.
	id2, err := f.svc.CreateWith(ctx, f.admin, tid, Params{Email: "fresh@x.test"})
	if err != nil || id2 == "" {
		t.Fatalf("%q %v", id2, err)
	}

	// Escalation applies to plain invitations (imported or not): refused
	// before any row.
	f.esc.deny["r-owner"] = true
	before, beforeOb := len(f.ms.Invitations), len(f.ms.Outbox)
	for _, addr := range []string{"boris@x.test", "someone@x.test"} {
		if id, err := f.svc.CreateWith(ctx, f.admin, tid, Params{Email: addr, RoleIDs: []string{"r-owner"}}); !errors.Is(err, authz.ErrSelfEscalation) || id != "" {
			t.Fatalf("%s: %q %v", addr, id, err)
		}
	}
	if len(f.ms.Invitations) != before || len(f.ms.Outbox) != beforeOb || f.status(t, "u-imp2") != "imported" {
		t.Fatal("escalation refusal wrote rows")
	}
	// An active account is still refused silently (unchanged behaviour).
	delete(f.esc.deny, "r-owner")
	if id, err := f.svc.CreateWith(ctx, f.admin, tid, Params{Email: "exists@x.test"}); err != nil || id != "" {
		t.Fatalf("active account: %q %v", id, err)
	}
}

// TestAcceptActivation: accepting an activation token activates the
// imported-then-invited row in place — password set, roles bound, groups
// joined — and the directory link row stays.
func TestAcceptActivation(t *testing.T) {
	f := actSetup(t)
	ctx := context.Background()
	_ = f.ms.ReplaceGroupRoles(ctx, tid, "g-fin", "", nil)
	items, err := f.svc.Activate(ctx, f.admin, tid, []string{"u-imp1"}, Params{RoleIDs: []string{"r-auditor"}, GroupIDs: []string{"g-fin"}})
	if err != nil || items[0].Outcome != OutcomeInvited {
		t.Fatalf("%+v %v", items, err)
	}
	tok := tokenFrom(t, f.ob, f.outboxFor("ana@x.test")[0])
	acc, err := f.svc.Accept(ctx, tok, "", "long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if acc.User.ID != "u-imp1" || acc.User.Status != "active" || acc.User.PasswordHash == nil {
		t.Fatalf("accepted %+v", acc.User)
	}
	u, _ := f.ms.User(ctx, tid, "u-imp1")
	if u.Status != "active" || u.PasswordHash == nil || u.FirstName != "Ana" || u.LastName != "Petrova" {
		t.Fatalf("stored %+v", u)
	}
	if ok, _, err := crypto.VerifyPassword("long-enough-password", *u.PasswordHash); err != nil || !ok {
		t.Fatalf("password not set: %v %v", ok, err)
	}
	if roles, _ := f.ms.Roles(ctx, tid, "u-imp1"); len(roles) != 1 || roles[0] != "auditor" {
		t.Fatalf("roles %v", roles)
	}
	if ok, _ := f.ms.IsGroupMember(ctx, tid, "g-fin", "u-imp1"); !ok {
		t.Fatal("group not joined")
	}
	for _, tu := range []authz.Tuple{
		authz.MembershipTuple(tid, "u-imp1", "member"),
		authz.RoleAssignmentTuple(tid, "auditor", "u-imp1"),
		authz.GroupMembershipTuple(tid, "g-fin", "u-imp1"),
	} {
		if ok, _ := f.fga.Check(ctx, tu); !ok {
			t.Fatalf("tuple missing: %+v", tu)
		}
	}
	if l, _ := f.ms.LinksByUIDs(ctx, tid, connID, []string{"uid-u-imp1"}); len(l) != 1 || l["uid-u-imp1"].UserID != "u-imp1" {
		t.Fatalf("link row must be kept: %+v", l)
	}
	n := 0
	for _, x := range f.ms.Users {
		if x.TenantID == tid && x.Email == "ana@x.test" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("user rows %d", n)
	}
}
