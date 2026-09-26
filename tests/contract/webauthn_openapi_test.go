package contract

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/httpapi"
)

// Feature 018: the security-key surface. Signed-in mutations carry the CSRF
// header, the sign-in steps are public (a pending challenge authenticates
// them), request bodies are closed objects and no response documents key
// material.
func TestOpenAPIWebAuthn(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	routes := []struct {
		r      httpapi.Route
		public bool
	}{
		{httpapi.Route{Method: "POST", Path: "/api/v1/signin/mfa/webauthn/options"}, true},
		{httpapi.Route{Method: "POST", Path: "/api/v1/signin/mfa/webauthn"}, true},
		{httpapi.Route{Method: "GET", Path: "/api/v1/me/mfa"}, false},
		{httpapi.Route{Method: "POST", Path: "/api/v1/me/mfa/webauthn/register/options"}, false},
		{httpapi.Route{Method: "POST", Path: "/api/v1/me/mfa/webauthn/register"}, false},
		{httpapi.Route{Method: "PATCH", Path: "/api/v1/me/mfa/webauthn/{id}"}, false},
		{httpapi.Route{Method: "DELETE", Path: "/api/v1/me/mfa/webauthn/{id}"}, false},
		{httpapi.Route{Method: "POST", Path: "/api/v1/me/mfa/stepup/options"}, false},
		{httpapi.Route{Method: "GET", Path: "/api/v1/admin/users/{id}/mfa"}, false},
		{httpapi.Route{Method: "POST", Path: "/api/v1/admin/users/{id}/mfa/reset"}, false},
	}
	for _, rt := range routes {
		op := operation(doc, rt.r)
		if op == nil {
			t.Errorf("%s: not declared", rt.r)
			continue
		}
		public := op.Security != nil && len(*op.Security) == 0
		if public != rt.public {
			t.Errorf("%s: public=%v, want %v", rt.r, public, rt.public)
		}
		if rt.r.Method != "GET" && !rt.public && !hasCSRF(op) {
			t.Errorf("%s: mutation without the required X-CSRF-Token header", rt.r)
		}
		if strings.HasPrefix(rt.r.Path, "/api/v1/me/mfa/webauthn/{id}") && !hasUUIDPathID(op) {
			t.Errorf("%s: key id must be a required uuid", rt.r)
		}
		if ref := bodySchemaRef(op); ref != nil && ref.Value != nil {
			if ap := ref.Value.AdditionalProperties.Has; ap == nil || *ap {
				t.Errorf("%s: request body must be a closed object", rt.r)
			}
		}
	}
	key := doc.Components.Schemas["SecurityKey"]
	if key == nil || key.Value == nil {
		t.Fatal("SecurityKey schema missing")
	}
	for name := range key.Value.Properties {
		if strings.Contains(name, "public") || strings.Contains(name, "credential") || strings.Contains(name, "aaguid") {
			t.Errorf("SecurityKey exposes %s", name)
		}
	}
}
