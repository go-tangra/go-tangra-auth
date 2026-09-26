package authclient

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
)

func wardenRegistration() Registration {
	return Registration{
		Module: "warden", DisplayName: "Warden",
		Permissions: []Permission{{Resource: "secrets", Action: "read", Description: "Read secrets"}, {Resource: "secrets", Action: "write"}, {Resource: "backup", Action: "manage"}},
		Roles: []ModuleRole{
			{Slug: "administrator", DisplayName: "Warden administrator", Permissions: []string{"secrets:read", "secrets:write", "backup:manage"}},
			{Slug: "viewer", DisplayName: "Warden viewer", Description: "Read secrets granted to the user", Permissions: []string{"secrets:read"}},
		},
		BuiltinGrants: map[string][]string{"owner": {"secrets:read", "backup:manage"}, "admin": {"backup:manage"}},
	}
}

// T043: Validate enforces the limits, grammars and the own-permission rule
// before anything is sent.
func TestRegistrationValidate(t *testing.T) {
	if err := wardenRegistration().Validate(); err != nil {
		t.Fatal(err)
	}
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "secrets:read"
		}
		return out
	}
	for name, mut := range map[string]func(*Registration){
		"module empty":         func(r *Registration) { r.Module = "" },
		"module grammar":       func(r *Registration) { r.Module = "Warden" },
		"module long":          func(r *Registration) { r.Module = strings.Repeat("w", 33) },
		"display long":         func(r *Registration) { r.DisplayName = strings.Repeat("W", 121) },
		"display control":      func(r *Registration) { r.DisplayName = "War\nden" },
		"permission grammar":   func(r *Registration) { r.Permissions[0].Resource = "Secrets" },
		"permission action":    func(r *Registration) { r.Permissions[0].Action = "read:all" },
		"permission duplicate": func(r *Registration) { r.Permissions = append(r.Permissions, r.Permissions[0]) },
		"description long":     func(r *Registration) { r.Permissions[0].Description = strings.Repeat("d", 257) },
		"too many permissions": func(r *Registration) { r.Permissions = make([]Permission, 201) },
		"too many roles":       func(r *Registration) { r.Roles = make([]ModuleRole, 21) },
		"role slug":            func(r *Registration) { r.Roles[0].Slug = "Admin" },
		"role slug dot":        func(r *Registration) { r.Roles[0].Slug = "a.b" },
		"role slug long":       func(r *Registration) { r.Roles[0].Slug = strings.Repeat("a", 33) },
		"role duplicate":       func(r *Registration) { r.Roles[1].Slug = r.Roles[0].Slug },
		"role name empty":      func(r *Registration) { r.Roles[0].DisplayName = " " },
		"role name long":       func(r *Registration) { r.Roles[0].DisplayName = strings.Repeat("n", 121) },
		"role description":     func(r *Registration) { r.Roles[0].Description = strings.Repeat("d", 257) },
		"role no permissions":  func(r *Registration) { r.Roles[0].Permissions = nil },
		"role too many":        func(r *Registration) { r.Roles[0].Permissions = many(201) },
		"role foreign":         func(r *Registration) { r.Roles[1].Permissions = []string{"users:manage"} },
		"role other module":    func(r *Registration) { r.Roles[1].Permissions = []string{"ipam:secrets:read"} },
		"grant role":           func(r *Registration) { r.BuiltinGrants["viewer"] = []string{"secrets:read"} },
		"grant foreign":        func(r *Registration) { r.BuiltinGrants["member"] = []string{"users:manage"} },
		"tenant id":            func(r *Registration) { r.TenantIDs = []string{"acme"} },
	} {
		r := wardenRegistration()
		mut(&r)
		if err := r.Validate(); !errors.Is(err, ErrInvalidRegistration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A role may name its own module's permissions in qualified form.
	r := wardenRegistration()
	r.Roles[1].Permissions = []string{"warden:secrets:read"}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

// T043: Request carries module, display name, the complete role set
// (declares_roles) and deterministic grants.
func TestRegistrationRequest(t *testing.T) {
	req := wardenRegistration().Request()
	if req.GetModule() != "warden" || req.GetModuleDisplayName() != "Warden" || !req.GetDeclaresRoles() || len(req.GetPermissions()) != 3 || len(req.GetRoles()) != 2 {
		t.Fatalf("%v", req)
	}
	if req.GetRoles()[1].GetDescription() != "Read secrets granted to the user" || req.GetPermissions()[0].GetDescription() != "Read secrets" {
		t.Fatalf("%v", req)
	}
	if g := req.GetBuiltinGrants(); len(g) != 2 || g[0].GetRole() != "admin" || g[1].GetRole() != "owner" || strings.Join(g[1].GetPermissions(), ",") != "secrets:read,backup:manage" {
		t.Fatalf("%v", g)
	}
	// Qualified role permissions are sent short.
	r := wardenRegistration()
	r.Roles[1].Permissions = []string{"warden:secrets:read"}
	if got := r.Request().GetRoles()[1].GetPermissions(); len(got) != 1 || got[0] != "secrets:read" {
		t.Fatalf("%v", got)
	}
	// A module without roles still declares its (empty) role set.
	r.Roles = nil
	if !r.Request().GetDeclaresRoles() || len(r.Request().GetRoles()) != 0 {
		t.Fatal("empty role set")
	}
}

// fakeConn answers Authorization/RegisterPermissions in memory.
type fakeConn struct {
	got    *authv1.RegisterPermissionsRequest
	method string
	resp   *authv1.RegisterPermissionsResponse
	err    error
}

func (f *fakeConn) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	f.method = method
	f.got = proto.Clone(args.(*authv1.RegisterPermissionsRequest)).(*authv1.RegisterPermissionsRequest)
	if f.err != nil {
		return f.err
	}
	proto.Merge(reply.(*authv1.RegisterPermissionsResponse), f.resp)
	return nil
}

func (f *fakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("no streams")
}

// T043: Register validates, sends, and logs every skipped grant (warn) and
// rejected role (error); an invalid registration never reaches auth.
func TestRegistrationRegister(t *testing.T) {
	conn := &fakeConn{resp: &authv1.RegisterPermissionsResponse{Registered: 6, RolesUpserted: 2, RolesRetired: []string{"old"},
		SkippedGrants: []*authv1.SkippedGrant{{Role: "operator", Tenants: 3, SampleTenantIds: []string{"t1"}, Reason: "role_missing"}},
		RoleErrors:    []*authv1.RoleError{{Slug: "viewer", Reason: "foreign_permission"}}}}
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	resp, err := wardenRegistration().Register(context.Background(), conn, log)
	if err != nil || resp.GetRegistered() != 6 || conn.method != authv1.Authorization_RegisterPermissions_FullMethodName || conn.got.GetModule() != "warden" {
		t.Fatalf("%v %v %s", resp, err, conn.method)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", "role=operator", "tenants=3", "level=ERROR", "slug=viewer", "reason=foreign_permission", "retired"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %q: %s", want, out)
		}
	}
	// Invalid: nothing sent.
	conn = &fakeConn{resp: &authv1.RegisterPermissionsResponse{}}
	bad := wardenRegistration()
	bad.Roles[1].Permissions = []string{"users:manage"}
	if _, err := bad.Register(context.Background(), conn, nil); !errors.Is(err, ErrInvalidRegistration) || conn.got != nil {
		t.Fatalf("%v sent=%v", err, conn.got != nil)
	}
	// Transport errors are returned; a nil logger is allowed.
	conn = &fakeConn{err: errors.New("unavailable")}
	if _, err := wardenRegistration().Register(context.Background(), conn, nil); err == nil {
		t.Fatal("error swallowed")
	}
}
