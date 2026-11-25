package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
)

const (
	mdTenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	mdOther  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	// Member ids, ordered as listed.
	mdDana  = "0190f7c2-6a3e-7c1a-9b2e-000000000001" // direct teleport role
	mdBob   = "0190f7c2-6a3e-7c1a-9b2e-000000000002" // teleport role via group
	mdCarol = "0190f7c2-6a3e-7c1a-9b2e-000000000003" // only another module's role
	mdEve   = "0190f7c2-6a3e-7c1a-9b2e-000000000004" // deactivated
	mdIvy   = "0190f7c2-6a3e-7c1a-9b2e-000000000005" // invited
	mdFrank = "0190f7c2-6a3e-7c1a-9b2e-000000000006" // no roles, no groups
	mdZed   = "0190f7c2-6a3e-7c1a-9b2e-000000000009" // other tenant
	mdGroup = "0190f7c2-6a3e-7c1a-9b2e-0000000000a1"
	mdOGrp  = "0190f7c2-6a3e-7c1a-9b2e-0000000000a2" // other tenant's group
)

func teleportCtx() context.Context {
	return tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/teleport"})
}

func modRole(id, tid, module, slug string) store.Role {
	return store.Role{ID: id, TenantID: tid, Slug: "m." + module + "." + slug, DisplayName: slug, Origin: store.OriginModule, Module: module, ModuleSlug: slug}
}

// memberDetailsFixture: two tenants with direct, group, foreign-module and
// custom roles; inactive members; a same-shaped member in the other tenant.
func memberDetailsFixture(t *testing.T) *ProfilesServer {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	for _, u := range []store.User{
		{ID: mdDana, TenantID: mdTenant, Email: "dana@x.test", DisplayName: "Dana Kovač", Phone: "+385911234567", Status: "active", MFAEnabled: true, MFASecretEnc: []byte("sealed")},
		{ID: mdBob, TenantID: mdTenant, Email: "bob@x.test", DisplayName: "Bob Stone", Status: "active"},
		{ID: mdCarol, TenantID: mdTenant, Email: "carol@x.test", DisplayName: "Carol", Status: "active"},
		{ID: mdEve, TenantID: mdTenant, Email: "eve@x.test", DisplayName: "Eve", Status: "deactivated"},
		{ID: mdIvy, TenantID: mdTenant, Email: "ivy@x.test", DisplayName: "Ivy", Status: "invited"},
		{ID: mdFrank, TenantID: mdTenant, Email: "frank@x.test", DisplayName: "Frank DANA", Status: "active"},
		{ID: mdZed, TenantID: mdOther, Email: "dana@other.test", DisplayName: "Dana Foreign", Status: "active"},
	} {
		ms.AddUser(u)
	}
	for _, r := range []store.Role{
		modRole("r-tp-access", mdTenant, "teleport", "access"),
		modRole("r-tp-admin", mdTenant, "teleport", "admin"),
		modRole("r-tp-auditor", mdTenant, "teleport", "auditor"),
		modRole("r-wd-viewer", mdTenant, "warden", "viewer"),
		{ID: "r-custom", TenantID: mdTenant, Slug: "teleport-like", DisplayName: "Custom", Origin: store.OriginCustom},
		{ID: "r-builtin", TenantID: mdTenant, Slug: "admin", DisplayName: "Admin", Builtin: true, Origin: store.OriginBuiltin},
		modRole("r-o-tp-admin", mdOther, "teleport", "admin"),
	} {
		ms.AddRole(r)
	}
	bind := func(tid, uid string, roles ...string) {
		if err := ms.ReplaceBindings(ctx, tid, uid, "", roles); err != nil {
			t.Fatal(err)
		}
	}
	bind(mdTenant, mdDana, "r-tp-admin", "r-tp-access", "r-wd-viewer", "r-builtin")
	bind(mdTenant, mdCarol, "r-wd-viewer", "r-custom")
	bind(mdTenant, mdEve, "r-tp-admin")
	bind(mdOther, mdZed, "r-o-tp-admin")
	if err := ms.CreateGroup(ctx, store.Group{ID: mdGroup, TenantID: mdTenant, Name: "Ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.AddGroupMembers(ctx, mdTenant, mdGroup, "", []string{mdDana, mdBob, mdEve}); err != nil {
		t.Fatal(err)
	}
	if err := ms.ReplaceGroupRoles(ctx, mdTenant, mdGroup, "", []string{"r-tp-access", "r-tp-auditor", "r-wd-viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := ms.CreateGroup(ctx, store.Group{ID: mdOGrp, TenantID: mdOther, Name: "Ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.AddGroupMembers(ctx, mdOther, mdOGrp, "", []string{mdZed}); err != nil {
		t.Fatal(err)
	}
	return &ProfilesServer{Profiles: user.NewProfiles(ms, nil)}
}

func byID(ms []*authv1.MemberDetail) map[string]*authv1.MemberDetail {
	out := map[string]*authv1.MemberDetail{}
	for _, m := range ms {
		out[m.GetUserId()] = m
	}
	return out
}

func ids(ms []*authv1.MemberDetail) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.GetUserId())
	}
	return out
}

func TestProfilesMembersRolesAndGroups(t *testing.T) {
	srv := memberDetailsFixture(t)
	res, err := srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant})
	if err != nil {
		t.Fatal(err)
	}
	// Active members of the tenant only, ordered by id; inactive (deactivated,
	// invited) and foreign members are omitted.
	if got, want := ids(res.GetMembers()), []string{mdDana, mdBob, mdCarol, mdFrank}; !slices.Equal(got, want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	if res.GetNextCursor() != "" {
		t.Fatalf("single page must have no cursor: %q", res.GetNextCursor())
	}
	m := byID(res.GetMembers())
	// Direct bindings and group roles, deduplicated and sorted; other modules',
	// custom and built-in roles excluded; slugs are the module's own.
	if d := m[mdDana]; d.GetLogin() != "dana@x.test" || d.GetDisplayName() != "Dana Kovač" ||
		!slices.Equal(d.GetRoles(), []string{"access", "admin", "auditor"}) || !slices.Equal(d.GetGroupIds(), []string{mdGroup}) {
		t.Fatalf("dana %+v", d)
	}
	if b := m[mdBob]; !slices.Equal(b.GetRoles(), []string{"access", "auditor"}) || !slices.Equal(b.GetGroupIds(), []string{mdGroup}) {
		t.Fatalf("bob (roles via group) %+v", b)
	}
	if c := m[mdCarol]; len(c.GetRoles()) != 0 || len(c.GetGroupIds()) != 0 {
		t.Fatalf("carol holds only another module's and a custom role: %+v", c)
	}
	if f := m[mdFrank]; len(f.GetRoles()) != 0 || len(f.GetGroupIds()) != 0 || f.GetLogin() != "frank@x.test" {
		t.Fatalf("frank %+v", f)
	}
	// Built-in roles are reported apart (tenant administrators); custom and
	// module roles never appear there.
	if d := m[mdDana]; !slices.Equal(d.GetBuiltinRoles(), []string{"admin"}) {
		t.Fatalf("dana built-in roles %v", d.GetBuiltinRoles())
	}
	for _, id := range []string{mdBob, mdCarol, mdFrank} {
		if b := m[id].GetBuiltinRoles(); len(b) != 0 {
			t.Fatalf("%s holds no built-in role, got %v", id, b)
		}
	}
	for _, d := range res.GetMembers() {
		s := d.String()
		if strings.Contains(s, "+385") || strings.Contains(s, "sealed") || strings.Contains(s, "warden") || strings.Contains(s, "viewer") {
			t.Fatalf("phone, secrets and foreign roles must never be returned: %s", s)
		}
	}
}

func TestProfilesMembersCallerModule(t *testing.T) {
	srv := memberDetailsFixture(t)
	// Another module sees its own roles only.
	wctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/warden"})
	res, err := srv.Members(wctx, &authv1.ListMemberDetailsRequest{TenantId: mdTenant, UserIds: []string{mdDana, mdBob, mdCarol}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.GetMembers() {
		if !slices.Equal(d.GetRoles(), []string{"viewer"}) {
			t.Fatalf("warden roles of %s: %v", d.GetUserId(), d.GetRoles())
		}
	}
	// A caller whose identity names no module is refused; no identity at all
	// is unauthenticated.
	for _, id := range []string{"", "spiffe://example.org/gateway", "spiffe://example.org/svc/Bad_Name", "not-a-spiffe-id", "spiffe://example.org/svc/"} {
		ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: id})
		if _, err := srv.Members(ctx, &authv1.ListMemberDetailsRequest{TenantId: mdTenant}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("caller %q → %v", id, err)
		}
	}
	if _, err := srv.Members(context.Background(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous → %v", err)
	}
	// A signed-in user (not a service) is refused even with a module-like id.
	uctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, TenantID: mdTenant, UserID: mdDana, ServiceID: "spiffe://example.org/svc/teleport"})
	if _, err := srv.Members(uctx, &authv1.ListMemberDetailsRequest{TenantId: mdTenant}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("user actor → %v", err)
	}
}

func TestProfilesMembersTenantIsolation(t *testing.T) {
	srv := memberDetailsFixture(t)
	res, err := srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdOther})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetMembers()) != 1 {
		t.Fatalf("other tenant %v", ids(res.GetMembers()))
	}
	z := res.GetMembers()[0]
	if z.GetUserId() != mdZed || !slices.Equal(z.GetRoles(), []string{"admin"}) || !slices.Equal(z.GetGroupIds(), []string{mdOGrp}) {
		t.Fatalf("zed %+v", z)
	}
	// Asking tenant A for tenant B's member (and the reverse) yields nothing.
	res, err = srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant, UserIds: []string{mdZed}})
	if err != nil || len(res.GetMembers()) != 0 {
		t.Fatalf("foreign id through tenant A: %v %v", res, err)
	}
	res, err = srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdOther, UserIds: []string{mdDana, mdBob}})
	if err != nil || len(res.GetMembers()) != 0 {
		t.Fatalf("tenant A ids through tenant B: %v %v", res, err)
	}
	res, err = srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant, Query: "foreign"})
	if err != nil || len(res.GetMembers()) != 0 {
		t.Fatalf("query must not cross tenants: %v %v", res, err)
	}
}

func TestProfilesMembersQueryAndFilter(t *testing.T) {
	srv := memberDetailsFixture(t)
	q := func(req *authv1.ListMemberDetailsRequest) []string {
		t.Helper()
		req.TenantId = mdTenant
		res, err := srv.Members(teleportCtx(), req)
		if err != nil {
			t.Fatal(err)
		}
		return ids(res.GetMembers())
	}
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"DANA", []string{mdDana, mdFrank}}, // login "dana@…" and display name "Frank DANA"
		{"dana@x", []string{mdDana}},        // login only
		{"stone", []string{mdBob}},          // display name, case-insensitive
		{"kovač", []string{mdDana}},         // non-ASCII display name
		{"  bob  ", []string{mdBob}},        // trimmed
		{"eve", nil},                        // inactive
		{"%", nil},                          // LIKE metacharacters are literal
		{"_", nil},
		{"x.test", []string{mdDana, mdBob, mdCarol, mdFrank}},
	} {
		if got := q(&authv1.ListMemberDetailsRequest{Query: c.query}); !slices.Equal(got, c.want) && (len(got) != 0 || len(c.want) != 0) {
			t.Errorf("query %q: %v, want %v", c.query, got, c.want)
		}
	}
	// user_ids filter: the active ones among them, unknown/inactive/foreign omitted.
	if got := q(&authv1.ListMemberDetailsRequest{UserIds: []string{mdFrank, mdEve, mdZed, "nope", mdBob, mdBob}}); !slices.Equal(got, []string{mdBob, mdFrank}) {
		t.Fatalf("filter %v", got)
	}
	// Filter and query combine.
	if got := q(&authv1.ListMemberDetailsRequest{UserIds: []string{mdDana, mdBob}, Query: "dana"}); !slices.Equal(got, []string{mdDana}) {
		t.Fatalf("filter+query %v", got)
	}
}

func TestProfilesMembersPaging(t *testing.T) {
	ms := memstore.New()
	ctx := context.Background()
	ms.AddRole(modRole("r-tp", mdTenant, "teleport", "access"))
	for i := 0; i < 2500; i++ {
		id := fmt.Sprintf("0190f7c2-6a3e-7c1a-9b2e-%012d", i)
		st := "active"
		if i%100 == 0 {
			st = "deactivated"
		}
		name := "Member"
		if i%10 == 0 {
			name = "Needle"
		}
		ms.AddUser(store.User{ID: id, TenantID: mdTenant, Email: fmt.Sprintf("u%d@x.test", i), DisplayName: name, Status: st})
		if i%2 == 0 {
			if err := ms.ReplaceBindings(ctx, mdTenant, id, "", []string{"r-tp"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	srv := &ProfilesServer{Profiles: user.NewProfiles(ms, nil)}
	walk := func(limit int32, query string) ([]string, int) {
		t.Helper()
		var all []string
		cursor, pages := "", 0
		for {
			res, err := srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant, Cursor: cursor, Limit: limit, Query: query})
			if err != nil {
				t.Fatal(err)
			}
			if limit > 0 && len(res.GetMembers()) > int(limit) {
				t.Fatalf("page of %d over limit %d", len(res.GetMembers()), limit)
			}
			for _, m := range res.GetMembers() {
				all = append(all, m.GetUserId())
				if want := m.GetUserId()[len(m.GetUserId())-1]%2 == 0; want != (len(m.GetRoles()) == 1) {
					t.Fatalf("roles of %s: %v", m.GetUserId(), m.GetRoles())
				}
			}
			pages++
			if cursor = res.GetNextCursor(); cursor == "" {
				return all, pages
			}
		}
	}
	all, pages := walk(1000, "")
	if len(all) != 2475 || pages != 3 {
		t.Fatalf("members %d pages %d", len(all), pages)
	}
	if !slices.IsSorted(all) || len(slices.Compact(slices.Clone(all))) != len(all) {
		t.Fatal("not ordered or duplicated")
	}
	if all2, pages := walk(0, ""); len(all2) != 2475 || pages != 3 {
		t.Fatalf("default limit: %d members %d pages", len(all2), pages)
	}
	// The query pages the same way (by id, cursor = last id of a full page).
	needles, pages := walk(100, "needle")
	if len(needles) != 225 || pages != 3 || !slices.IsSorted(needles) {
		t.Fatalf("needles %d pages %d", len(needles), pages)
	}
}

func TestProfilesMembersBounds(t *testing.T) {
	srv := memberDetailsFixture(t)
	for _, req := range []*authv1.ListMemberDetailsRequest{
		{TenantId: "x"},
		{TenantId: ""},
		{TenantId: mdTenant, Limit: -1},
		{TenantId: mdTenant, Limit: 1001},
		{TenantId: mdTenant, UserIds: make([]string, 1001)},
		{TenantId: mdTenant, Query: strings.Repeat("a", 101)},
		{TenantId: mdTenant, Query: "a\x00b"},
	} {
		if _, err := srv.Members(teleportCtx(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%v → %v", req, err)
		}
	}
	for _, req := range []*authv1.ListMemberDetailsRequest{
		{TenantId: mdTenant, Limit: 1},
		{TenantId: mdTenant, Limit: 1000},
		{TenantId: mdTenant, UserIds: make([]string, 1000)},
		{TenantId: mdTenant, Query: strings.Repeat("ž", 100)},
	} {
		if _, err := srv.Members(teleportCtx(), req); err != nil {
			t.Fatalf("%v → %v", req, err)
		}
	}
	res, err := srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant, Limit: 1})
	if err != nil || len(res.GetMembers()) != 1 || res.GetMembers()[0].GetUserId() != mdDana || res.GetNextCursor() != mdDana {
		t.Fatalf("limit 1: %v %v", res, err)
	}
	res, err = srv.Members(teleportCtx(), &authv1.ListMemberDetailsRequest{TenantId: mdTenant, Limit: 2, Cursor: mdDana})
	if err != nil || !slices.Equal(ids(res.GetMembers()), []string{mdBob, mdCarol}) || res.GetNextCursor() != mdCarol {
		t.Fatalf("second page: %v %v", res, err)
	}
}
