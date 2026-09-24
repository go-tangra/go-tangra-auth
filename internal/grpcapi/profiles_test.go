package grpcapi

import (
	"context"
	"fmt"
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

func TestProfilesLookup(t *testing.T) {
	const tid, other = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	ms := memstore.New()
	av := "ab12"
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "dana@x.test", DisplayName: "Dana K", Phone: "+385911234567", AvatarID: &av, Status: "active"})
	ms.AddUser(store.User{ID: "u2", TenantID: tid, Email: "bob@x.test", DisplayName: "Bob", Status: "active"})
	ms.AddUser(store.User{ID: "u9", TenantID: other, Email: "f@x.test", DisplayName: "Foreign", Status: "active"})
	srv := &ProfilesServer{Profiles: user.NewProfiles(ms, nil)}
	ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/hello"})

	res, err := srv.Lookup(ctx, &authv1.LookupProfilesRequest{TenantId: tid, UserIds: []string{"u1", "u9", "u2", "nope"}})
	if err != nil || len(res.GetProfiles()) != 2 {
		t.Fatalf("%v %v", res, err)
	}
	for _, p := range res.GetProfiles() {
		if p.GetUserId() == "u1" && (p.GetDisplayName() != "Dana K" || p.GetAvatarUrl() != "/api/v1/users/u1/avatar/ab12") {
			t.Fatalf("%+v", p)
		}
		if strings.Contains(p.String(), "+385") {
			t.Fatal("phone must never be returned")
		}
	}
	for _, req := range []*authv1.LookupProfilesRequest{
		{TenantId: "not-a-uuid", UserIds: []string{"u1"}},
		{TenantId: tid},
		{TenantId: tid, UserIds: make([]string, 101)},
	} {
		if _, err := srv.Lookup(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%v → %v", req, err)
		}
	}
	// A caller without a service identity is refused.
	if _, err := srv.Lookup(context.Background(), &authv1.LookupProfilesRequest{TenantId: tid, UserIds: []string{"u1"}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous → %v", err)
	}
}

func TestProfilesListMembers(t *testing.T) {
	const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	ms := memstore.New()
	for i := 0; i < 2500; i++ {
		id := fmt.Sprintf("0190f7c2-6a3e-7c1a-9b2e-%012d", i)
		st := "active"
		if i%100 == 0 {
			st = "deactivated"
		}
		ms.AddUser(store.User{ID: id, TenantID: tid, Email: fmt.Sprintf("u%d@x.test", i), DisplayName: "U", Status: st})
	}
	ms.AddUser(store.User{ID: "0190f7c2-6a3e-7c1a-9b2e-ffffffffffff", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Email: "f@x.test", DisplayName: "F", Status: "active"})
	srv := &ProfilesServer{Profiles: user.NewProfiles(ms, nil)}
	ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/notification"})
	var all []string
	cursor := ""
	pages := 0
	for {
		res, err := srv.ListMembers(ctx, &authv1.ListMembersRequest{TenantId: tid, Cursor: cursor, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, res.GetUserIds()...)
		pages++
		cursor = res.GetNextCursor()
		if cursor == "" {
			break
		}
	}
	if len(all) != 2475 || pages != 3 {
		t.Fatalf("members %d pages %d", len(all), pages)
	}
	for i := 1; i < len(all); i++ {
		if all[i] <= all[i-1] {
			t.Fatal("not ordered")
		}
	}
	// Filter mode: the active ones among the given ids, foreign and unknown omitted.
	res, err := srv.ListMembers(ctx, &authv1.ListMembersRequest{TenantId: tid, UserIds: []string{all[0], "0190f7c2-6a3e-7c1a-9b2e-000000000000", "0190f7c2-6a3e-7c1a-9b2e-ffffffffffff", "nope"}})
	if err != nil || len(res.GetUserIds()) != 1 || res.GetUserIds()[0] != all[0] || res.GetNextCursor() != "" {
		t.Fatalf("filter %v %v", res, err)
	}
	for _, req := range []*authv1.ListMembersRequest{{TenantId: "x"}, {TenantId: tid, Limit: 5000}, {TenantId: tid, UserIds: make([]string, 1001)}} {
		if _, err := srv.ListMembers(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%v → %v", req, err)
		}
	}
	if _, err := srv.ListMembers(context.Background(), &authv1.ListMembersRequest{TenantId: tid}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous → %v", err)
	}
}
