package fuzz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func FuzzSlug(f *testing.F) {
	for _, s := range []string{"acme", "a-b", "-x", "API", "", "a\x00b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := tenant.ParseSlug(s)
		if err == nil && (out != s || strings.ToLower(s) != s || len(s) > 63 || strings.ContainsAny(s, "/:. \n")) {
			t.Fatalf("accepted %q", s)
		}
		if _, err := authz.ParseSlug(s); err == nil && (len(s) > 64 || strings.ContainsAny(s, "/:. \n")) {
			t.Fatalf("role slug accepted %q", s)
		}
	})
}

func FuzzPermissionRef(f *testing.F) {
	for _, s := range []string{"invoices:read", "a:b:c", ":", "x:", "A:b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := authz.ParsePermissionRef(s)
		if err != nil {
			return
		}
		if p.String() != s {
			t.Fatalf("round trip %q → %q", s, p.String())
		}
		obj := authz.PermissionObject(tid, p)
		if got, err := authz.ObjectTenant(obj); err != nil || got != tid {
			t.Fatalf("object %q: %s %v", obj, got, err)
		}
	})
}

func FuzzFGAObjectID(f *testing.F) {
	for _, s := range []string{"tenant:" + tid, "role:" + tid + "/x", "permission:" + tid + "/a:b", "permission:" + tid + "/warden~backup~manage", "permission:" + tid + "/backup~manage", "user:u", "tenant:/", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := authz.ObjectTenant(s)
		if err == nil && !tenantctx.ValidTenantID(got) {
			t.Fatalf("%q yielded invalid tenant %q", s, got)
		}
		if err == nil && !strings.Contains(s, got) {
			t.Fatalf("%q → %q not contained", s, got)
		}
		// Feature 019: a module-qualified permission object never parses into
		// another tenant, and parse∘format is the identity.
		if ptid, ref, err := permref.ParseObject(s); err == nil {
			if ptid != got || ref.Object(ptid) != s {
				t.Fatalf("%q → %q %+v (object tenant %q)", s, ptid, ref, got)
			}
		}
	})
}

// FuzzQualifiedRef checks the module-qualified reference grammar (feature 019):
// accepted refs round-trip, never contain an object separator, and their
// object id stays in the tenant it was built for.
func FuzzQualifiedRef(f *testing.F) {
	for _, s := range []string{"warden:backup:manage", "backup:manage", "a:b:c:d", "w~x:a:b", "W:a:b", "::", "m:a/b:c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := permref.ParseAny(s)
		if err != nil {
			return
		}
		if r.String() != s || strings.ContainsAny(s, "~/ \n") {
			t.Fatalf("accepted %q → %+v", s, r)
		}
		obj := r.Object(tid)
		ot, back, err := permref.ParseObject(obj)
		if err != nil || ot != tid || back != r {
			t.Fatalf("object %q → %q %+v %v", obj, ot, back, err)
		}
		if got, err := authz.ObjectTenant(obj); err != nil || got != tid {
			t.Fatalf("object tenant %q: %q %v", obj, got, err)
		}
		if q, err := permref.Parse(s); err == nil && q.IsLegacy() {
			t.Fatalf("qualified parse produced legacy %q", s)
		}
	})
}

// FuzzModuleRoleSlug checks that module role slugs and custom slugs never
// overlap and that built-in slugs are never accepted as custom ones.
func FuzzModuleRoleSlug(f *testing.F) {
	for _, s := range []string{"m.warden.viewer", "viewer", "operator", "m..x", "m.a.b.c", "a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		mod, slug, ok := permref.ParseModuleRoleSlug(s)
		custom, cerr := permref.ParseCustomSlug(s)
		if ok && cerr == nil {
			t.Fatalf("%q is both a module role and a custom slug", s)
		}
		if ok {
			if back, err := permref.ModuleRoleSlug(mod, slug); err != nil || back != s {
				t.Fatalf("round trip %q → %q %v", s, back, err)
			}
		}
		if cerr == nil && (custom != s || permref.IsReserved(s) || strings.Contains(s, ".")) {
			t.Fatalf("custom accepted %q", s)
		}
	})
}

func FuzzOpenAPIBody(f *testing.F) {
	rt := testrt.NewTB(f, testutil.MustCA("example.org"), "auth")
	s, err := httpapi.NewHandler(rt)
	if err != nil {
		f.Fatal(err)
	}
	// Every declared body-bearing route on these paths gets a strict JSON handler.
	want := map[string]bool{"/api/v1/signin": true, "/api/v1/admin/invitations": true, "/api/v1/admin/policy": true}
	var routes []httpapi.Route
	for _, rt := range s.Declared() {
		if want[rt.Path] && (rt.Method == "POST" || rt.Method == "PUT") {
			routes = append(routes, rt)
			s.MustHandle(rt.Method, rt.Path, func(w http.ResponseWriter, r *http.Request) {
				var v map[string]any
				if err := httpapi.DecodeJSON(r, &v); err != nil {
					httpapi.Fail(w, r, nil, err)
					return
				}
				httpapi.WriteJSON(w, 200, v)
			})
		}
	}
	if len(routes) < 3 {
		f.Fatalf("expected body routes, got %v", routes)
	}
	for _, b := range []string{`{}`, `{"tenant":"a","email":"b","password":"c"}`, `[`, `null`, `{"a":` + strings.Repeat("[", 5000)} {
		f.Add(0, b)
	}
	f.Fuzz(func(t *testing.T, which int, body string) {
		rt := routes[abs(which)%len(routes)]
		r := httptest.NewRequest(rt.Method, "https://localhost"+rt.Path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code >= 500 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("body %.40q → %d %s", body, w.Code, w.Body.String())
		}
	})
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
