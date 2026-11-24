package contract

import (
	"context"
	"os"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/identity"
)

// TestEnrollmentPolicy pins who may call the enrollment RPCs in
// deploy/policy.yaml: TokenStatus (whether a join token was used) is the
// gateway's alone; every other service is refused.
func TestEnrollmentPolicy(t *testing.T) {
	f, err := os.Open("../../deploy/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := authz.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	may := func(svc, op string) bool {
		t.Helper()
		id, err := identity.ParseSPIFFEID("spiffe://example.org/svc/" + svc)
		if err != nil {
			t.Fatal(err)
		}
		return p.Authorize(context.Background(), id, "auth", op).Allowed
	}
	const status = "/auth.v1.Enrollment/TokenStatus"
	if d := p.Authorize(context.Background(), mustID(t, "spiffe://example.org/svc/gateway"), "auth", status); !d.Allowed || d.RuleID != "gateway-enrollment-status" {
		t.Fatalf("gateway TokenStatus: %+v", d)
	}
	for _, svc := range []string{"lcm", "notification", "deployer", "console", "portal", "gateway-evil"} {
		if may(svc, status) {
			t.Errorf("%s may call TokenStatus", svc)
		}
	}
	if !may("lcm", "/auth.v1.Enrollment/VerifyEnrollmentToken") || may("notification", "/auth.v1.Enrollment/VerifyEnrollmentToken") {
		t.Error("VerifyEnrollmentToken policy changed")
	}
}

func mustID(t *testing.T, s string) identity.SPIFFEID {
	t.Helper()
	id, err := identity.ParseSPIFFEID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestProfilesMembersPolicy pins who may list member details (login, the
// caller module's roles, group ids): the teleport module only, besides the
// gateway's catch-all forward rule. The other directory services keep
// Lookup/ListMembers and are refused Members.
func TestProfilesMembersPolicy(t *testing.T) {
	f, err := os.Open("../../deploy/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := authz.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	decide := func(svc, op string) authz.Decision {
		t.Helper()
		return p.Authorize(context.Background(), mustID(t, "spiffe://example.org/svc/"+svc), "auth", op)
	}
	const members = "/auth.v1.Profiles/Members"
	for _, op := range []string{"/auth.v1.Profiles/Lookup", "/auth.v1.Profiles/ListMembers", members} {
		if d := decide("teleport", op); !d.Allowed || d.RuleID != "teleport-directory" {
			t.Errorf("teleport %s: %+v", op, d)
		}
	}
	if decide("teleport", "/auth.v1.Profiles/Contacts").Allowed {
		t.Error("teleport may read e-mail contacts")
	}
	for _, svc := range []string{"notification", "asset", "ticket", "deployer", "signing", "hr", "lcm", "warden", "teleport-evil", "console", "portal"} {
		if decide(svc, members).Allowed {
			t.Errorf("%s may call Members", svc)
		}
	}
}
