package authz

import (
	openfga "github.com/openfga/go-sdk"

	"context"
	"errors"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

func TestIdentifiers(t *testing.T) {
	for _, ok := range []string{"a", "auditor", "a-b-9", "x1"} {
		if _, err := ParseSlug(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a b", "a/b", "a:b", string(make([]byte, 65))} {
		if _, err := ParseSlug(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	p, err := ParsePermissionRef("invoices:read")
	if err != nil || p.Resource != "invoices" || p.Action != "read" || p.String() != "invoices:read" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"", "read", "a:b:c", ":read", "inv:", "Inv:read", "a/b:c", "a:b c"} {
		if _, err := ParsePermissionRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if o := PermissionObject(tA, p); o != "permission:"+tA+"/invoices~read" {
		t.Fatal(o)
	}
	if GroupMembers(tA, "g1") != "group:"+tA+"/g1#member" {
		t.Fatal(GroupMembers(tA, "g1"))
	}
	for obj, want := range map[string]string{TenantObject(tA): tA, RoleObject(tB, "r"): tB, PermissionObject(tA, p): tA, GroupObject(tB, "g1"): tB} {
		if got, err := ObjectTenant(obj); err != nil || got != want {
			t.Errorf("%s → %s %v", obj, got, err)
		}
	}
	for _, bad := range []string{"", "user:u1", "tenant:", "role:nope/x", "permission:" + tA, "tenant:not-a-uuid", "doc:" + tA + "/x", "group:" + tA} {
		if _, err := ObjectTenant(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func sysCtx() context.Context {
	return tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
}

func TestBootstrapIdempotent(t *testing.T) {
	f := NewFake()
	s1, m1, err := Bootstrap(context.Background(), f, "auth")
	if err != nil {
		t.Fatal(err)
	}
	s2, m2, err := Bootstrap(context.Background(), f, "auth")
	if err != nil || s1 != s2 || m1 != m2 || len(f.Stores) != 1 || f.Models != 1 {
		t.Fatalf("not idempotent: %s/%s %s/%s %v", s1, m1, s2, m2, err)
	}
}

func TestChecksWritesAndTenantGuard(t *testing.T) {
	ctx := sysCtx()
	f := NewFake()
	kv := cache.New(cache.NewMemory())
	var refusals int
	c := New(f, kv, func(tenantctx.Refusal) { refusals++ })
	read, _ := ParsePermissionRef("invoices:read")
	write, _ := ParsePermissionRef("invoices:write")
	if err := c.Write(ctx, tA, []Tuple{
		MembershipTuple(tA, "u1", "owner"),
		RoleTenantTuple(tA, "auditor"), PermissionTenantTuple(tA, read),
		GrantTuple(tA, "auditor", read), RoleAssignmentTuple(tA, "auditor", "u1"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Allowed(ctx, tA, "u1", read); err != nil || !ok {
		t.Fatalf("granted via role: %v %v", ok, err)
	}
	if ok, _ := c.Allowed(ctx, tA, "u1", write); ok {
		t.Fatal("write must not be granted")
	}
	if ok, _ := c.Allowed(ctx, tA, "u2", read); ok {
		t.Fatal("u2 not assigned")
	}
	if ok, _ := c.IsMember(ctx, tA, "u1"); !ok {
		t.Fatal("owner is member")
	}
	res, err := c.AllowedMany(ctx, tA, "u1", []PermissionRef{read, write})
	if err != nil || len(res) != 2 || !res[0] || res[1] {
		t.Fatalf("batch %v %v", res, err)
	}
	// Decision cache: served within TTL, invalidated by a write (tenant version bump).
	if err := c.Write(ctx, tA, nil, []Tuple{RoleAssignmentTuple(tA, "auditor", "u1")}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Allowed(ctx, tA, "u1", read); ok {
		t.Fatal("stale decision served after write")
	}
	// Cross-tenant objects are refused before the backend is touched.
	n := f.Len()
	if err := c.Write(ctx, tA, []Tuple{RoleAssignmentTuple(tB, "auditor", "u1")}, nil); !errors.Is(err, ErrCrossTenant) || f.Len() != n {
		t.Fatalf("cross-tenant write: %v", err)
	}
	if err := c.Write(ctx, tA, []Tuple{{User: TenantObject(tB), Relation: "tenant", Object: RoleObject(tA, "x")}}, nil); !errors.Is(err, ErrCrossTenant) {
		t.Fatalf("foreign tenant relation: %v", err)
	}
	if _, err := c.Allowed(ctx, tB, "u1", read); err != nil {
		t.Fatalf("system actor may check any tenant: %v", err)
	}
	// A user actor of tenant A can never ask about tenant B.
	uctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA})
	if _, err := c.Allowed(uctx, tB, "u1", read); err == nil || refusals != 1 {
		t.Fatalf("user cross-tenant check must be refused: %v (%d refusals)", err, refusals)
	}
	if _, err := c.Allowed(context.Background(), tA, "u1", read); err == nil {
		t.Fatal("no actor must be refused")
	}
	if _, err := c.Allowed(ctx, "bad", "u1", read); err == nil {
		t.Fatal("malformed tenant id must be refused")
	}
	// Without a cache the client still works.
	c2 := New(f, nil, nil)
	if ok, err := c2.IsMember(ctx, tA, "u1"); err != nil || !ok {
		t.Fatal(ok, err)
	}
}

func TestSDKBackendConfigAndModel(t *testing.T) {
	if _, err := NewSDKBackend(SDKConfig{}); err == nil {
		t.Fatal("url required")
	}
	if _, err := NewSDKBackend(SDKConfig{URL: "http://fga:8080", PresharedKey: "k"}); err == nil {
		t.Fatal("plaintext must be refused by default")
	}
	b, err := NewSDKBackend(SDKConfig{URL: "http://fga:8080", PresharedKey: "k", AllowPlaintext: true})
	if err != nil || b == nil {
		t.Fatal(err)
	}
	if _, err := NewSDKBackend(SDKConfig{URL: "https://fga:8443", PresharedKey: "k", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"}); err != nil {
		t.Fatal(err)
	}
	m := Model()
	if m.SchemaVersion != "1.1" || len(m.TypeDefinitions) != 5 {
		t.Fatalf("model %+v", m)
	}
	// Feature 004: roles are assignable to users and to group members.
	var role, group *openfga.TypeDefinition
	for i := range m.TypeDefinitions {
		switch m.TypeDefinitions[i].Type {
		case "role":
			role = &m.TypeDefinitions[i]
		case "group":
			group = &m.TypeDefinitions[i]
		}
	}
	if group == nil || (*group.Relations)["member"].This == nil {
		t.Fatalf("group type with a direct member relation expected: %+v", group)
	}
	refs := *(*role.Metadata.Relations)["assignee"].DirectlyRelatedUserTypes
	if len(refs) != 2 || refs[0].Type != "user" || refs[1].Type != "group" || refs[1].Relation == nil || *refs[1].Relation != "member" {
		t.Fatalf("role.assignee must be [user, group#member]: %+v", refs)
	}
	have := &openfga.AuthorizationModel{SchemaVersion: "1.1", TypeDefinitions: m.TypeDefinitions}
	if !SameModel(have, m) {
		t.Fatal("identical model must compare equal")
	}
	have.TypeDefinitions = have.TypeDefinitions[:3]
	if SameModel(have, m) {
		t.Fatal("different model must not compare equal")
	}
}

// TestFakeResolvesGroupMembership: the fake honours role#assignee: [user, group#member].
func TestFakeResolvesGroupMembership(t *testing.T) {
	f := NewFake()
	tid := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	p := PermissionRef{Resource: "invoices", Action: "read"}
	if err := f.Write(context.Background(), []Tuple{
		GroupTenantTuple(tid, "g1"),
		GroupMembershipTuple(tid, "g1", "u1"),
		GroupRoleTuple(tid, "g1", "reader"),
		{User: RoleAssignees(tid, "reader"), Relation: "granted", Object: PermissionObject(tid, p)},
	}, nil); err != nil {
		t.Fatal(err)
	}
	ok, _ := f.Check(context.Background(), Tuple{User: UserObject("u1"), Relation: "granted", Object: PermissionObject(tid, p)})
	if !ok {
		t.Fatal("member of a group holding the role must be granted")
	}
	ok, _ = f.Check(context.Background(), Tuple{User: UserObject("u2"), Relation: "granted", Object: PermissionObject(tid, p)})
	if ok {
		t.Fatal("non-member must not be granted")
	}
	// Group membership does not make anyone a tenant member/admin.
	ok, _ = f.Check(context.Background(), Tuple{User: UserObject("u1"), Relation: "member", Object: TenantObject(tid)})
	if ok {
		t.Fatal("group member is not a tenant member")
	}
	_ = f.Write(context.Background(), nil, []Tuple{GroupMembershipTuple(tid, "g1", "u1")})
	ok, _ = f.Check(context.Background(), Tuple{User: UserObject("u1"), Relation: "granted", Object: PermissionObject(tid, p)})
	if ok {
		t.Fatal("removed member must lose the grant")
	}
}
