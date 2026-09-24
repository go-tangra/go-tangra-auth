package contract

import (
	"testing"

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
