package fuzz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/httpapi"
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
	for _, s := range []string{"tenant:" + tid, "role:" + tid + "/x", "permission:" + tid + "/a:b", "user:u", "tenant:/", ""} {
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
