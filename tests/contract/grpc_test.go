package contract

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
)

// TestAuthV1Shapes pins the wire contract: services, methods and the fields
// verifiers depend on (contracts/token.md).
func TestAuthV1Shapes(t *testing.T) {
	fd := authv1.File_auth_v1_auth_proto
	want := map[string][]string{
		"Keys":          {"List"},
		"Sessions":      {"RevokedSince", "Watch", "Introspect", "Exchange", "MintToken"},
		"Authorization": {"Check", "BatchCheck", "RegisterPermissions"},
		"Profiles":      {"Lookup"},
	}
	for name, methods := range want {
		sd := fd.Services().ByName(protoreflect.Name(name))
		if sd == nil {
			t.Fatalf("service %s missing", name)
		}
		for _, m := range methods {
			if sd.Methods().ByName(protoreflect.Name(m)) == nil {
				t.Errorf("%s.%s missing", name, m)
			}
		}
	}
	if !fd.Services().ByName("Sessions").Methods().ByName("Watch").IsStreamingServer() {
		t.Error("Sessions.Watch must be server-streaming")
	}
	fields := map[string][]string{
		"Key":                {"kid", "kty", "crv", "public_key", "state", "not_after"},
		"Revocation":         {"ts", "kind", "subject_id", "tenant_id", "reason"},
		"IntrospectResponse": {"active", "reason", "user_id", "tenant_id", "session_id", "roles", "expires_at"},
		"CheckRequest":       {"tenant_id", "user_id", "resource", "action"},
		"ExchangeResponse":   {"identity", "access_token", "expires_at"},
		"SessionIdentity":    {"user_id", "tenant_id", "session_id", "roles", "amr", "operator", "display_name", "avatar_url"},
		"PublicProfile":      {"user_id", "display_name", "avatar_url"},
		"MintTokenRequest":   {"tenant_id", "session_id", "audience"},
	}
	for msg, names := range fields {
		md := fd.Messages().ByName(protoreflect.Name(msg))
		if md == nil {
			t.Fatalf("message %s missing", msg)
		}
		for _, f := range names {
			if md.Fields().ByName(protoreflect.Name(f)) == nil {
				t.Errorf("%s.%s missing", msg, f)
			}
		}
	}
}
