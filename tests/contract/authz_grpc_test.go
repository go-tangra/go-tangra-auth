package contract

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
)

// TestAuthorizationContract pins the decision RPC shapes and the reason vocabulary.
func TestAuthorizationContract(t *testing.T) {
	fd := authv1.File_auth_v1_auth_proto
	svc := fd.Services().ByName("Authorization")
	for _, m := range []string{"Check", "BatchCheck", "RegisterPermissions"} {
		if svc.Methods().ByName(protoreflect.Name(m)) == nil {
			t.Errorf("Authorization.%s missing", m)
		}
	}
	for msg, fields := range map[string][]string{
		"CheckResponse":              {"allowed", "reason", "policy_version"},
		"BatchCheckRequest":          {"tenant_id", "user_id", "permissions"},
		"RegisterPermissionsRequest": {"permissions", "tenant_ids"},
		"PermissionDef":              {"resource", "action", "description"},
	} {
		md := fd.Messages().ByName(protoreflect.Name(msg))
		for _, f := range fields {
			if md == nil || md.Fields().ByName(protoreflect.Name(f)) == nil {
				t.Errorf("%s.%s missing", msg, f)
			}
		}
	}
	for _, r := range []string{authz.ReasonNoPermission, authz.ReasonUserInactive, authz.ReasonTenantSuspended, authz.ReasonUnknownPermission} {
		switch r {
		case "no_permission", "user_inactive", "tenant_suspended", "unknown_permission":
		default:
			t.Errorf("reason %q outside the contract vocabulary", r)
		}
	}
}

// TestModuleRolesContract (feature 019, T020) pins the additive fields with
// their numbers, round-trips them, and checks that a message without them
// (an old client) decodes to the empty values auth treats as legacy.
func TestModuleRolesContract(t *testing.T) {
	fd := authv1.File_auth_v1_auth_proto
	for msg, fields := range map[string]map[string]protoreflect.FieldNumber{
		"CheckRequest":                {"module": 6},
		"PermissionRef":               {"resource": 1, "action": 2, "module": 3},
		"RegisterPermissionsRequest":  {"permissions": 1, "tenant_ids": 2, "builtin_grants": 3, "module": 4, "module_display_name": 5, "roles": 6, "declares_roles": 7},
		"ModuleRoleDef":               {"slug": 1, "display_name": 2, "description": 3, "permissions": 4},
		"RegisterPermissionsResponse": {"registered": 1, "skipped_grants": 2, "role_errors": 3, "roles_upserted": 4, "roles_retired": 5},
		"SkippedGrant":                {"role": 1, "tenants": 2, "sample_tenant_ids": 3, "reason": 4},
		"RoleError":                   {"slug": 1, "reason": 2},
	} {
		md := fd.Messages().ByName(protoreflect.Name(msg))
		if md == nil {
			t.Fatalf("%s missing", msg)
		}
		for f, num := range fields {
			fdesc := md.Fields().ByName(protoreflect.Name(f))
			if fdesc == nil || fdesc.Number() != num {
				t.Errorf("%s.%s: %v (want field %d)", msg, f, fdesc, num)
			}
		}
	}
	req := &authv1.RegisterPermissionsRequest{Module: "warden", ModuleDisplayName: "Warden", DeclaresRoles: true,
		Permissions: []*authv1.PermissionDef{{Resource: "secrets", Action: "read"}},
		Roles:       []*authv1.ModuleRoleDef{{Slug: "viewer", DisplayName: "Warden viewer", Description: "d", Permissions: []string{"secrets:read"}}}}
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var back authv1.RegisterPermissionsRequest
	if err := proto.Unmarshal(b, &back); err != nil || !proto.Equal(req, &back) {
		t.Fatalf("round trip: %v", err)
	}
	// An old client's request (fields 1-3 only) has no module and no roles.
	old, _ := proto.Marshal(&authv1.RegisterPermissionsRequest{Permissions: req.Permissions})
	var legacy authv1.RegisterPermissionsRequest
	if err := proto.Unmarshal(old, &legacy); err != nil || legacy.GetModule() != "" || legacy.GetDeclaresRoles() || len(legacy.GetRoles()) != 0 {
		t.Fatalf("old request: %v %v", &legacy, err)
	}
	// An old client ignores the new response fields.
	resp, _ := proto.Marshal(&authv1.RegisterPermissionsResponse{Registered: 2, RolesRetired: []string{"x"}, SkippedGrants: []*authv1.SkippedGrant{{Role: "operator"}}})
	var r authv1.RegisterPermissionsResponse
	if err := proto.Unmarshal(resp, &r); err != nil || r.GetRegistered() != 2 {
		t.Fatal(err)
	}
}
