package app

import (
	"slices"
	"testing"
)

// T071 (unit part): customer tenants get owner, admin, member and auditor;
// the platform tenant owner, admin, operator and auditor (research D6).
func TestBuiltinRolesFor(t *testing.T) {
	if got := BuiltinRolesFor("customer"); !slices.Equal(got, []string{"owner", "admin", "member", "auditor"}) {
		t.Fatalf("customer %v", got)
	}
	if got := BuiltinRolesFor("platform"); !slices.Equal(got, []string{"owner", "admin", "operator", "auditor"}) {
		t.Fatalf("platform %v", got)
	}
	// The result is a copy: callers cannot change the platform's set.
	BuiltinRolesFor("platform")[0] = "x"
	if BuiltinRolesFor("platform")[0] != "owner" {
		t.Fatal("shared slice")
	}
}

// Auth registers itself as module "auth" ("Authentication") with its
// console permissions and the built-in grants of its manifest.
func TestAuthRegistration(t *testing.T) {
	reg := authRegistration([]string{"t1"})
	if reg.Module != "auth" || reg.DisplayName != "Authentication" || len(reg.Permissions) != 9 || len(reg.Grants) != 5 || reg.Grants[0].Role != "admin" || reg.DeclaresRoles {
		t.Fatalf("%+v", reg)
	}
}
