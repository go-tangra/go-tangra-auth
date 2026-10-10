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
