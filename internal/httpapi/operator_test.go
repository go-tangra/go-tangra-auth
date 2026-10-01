package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/invite"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

const tP = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c11"

func TestOperatorPolicyAndClients(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	u.ms.AddTenant(store.Tenant{ID: tP, Slug: "platform", DisplayName: "Platform", Status: "active", Kind: "platform", Policy: []byte("{}")})
	h, _ := password.Hash("correct horse battery")
	u.ms.AddUser(store.User{ID: "op", TenantID: tP, Email: "ops@x.test", Status: "active", PasswordHash: &h})
	c := cache.New(cache.NewMemory())
	az := authz.New(authz.NewFake(), c, nil)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{7}, 32))
	inv := invite.New(u.ms, email.NewOutbox(env, nullSender{}, nil, 3, nil), az, aw, "https://auth.example.org")
	ts := tenant.New(u.ms, inv, u.sessions, az, c, aw)
	u.srv.RegisterUS5(US5Deps{Tenants: ts, Grants: tenant.NewGrants(u.ms, aw), Clients: u.ms, Audit: aw})
	u.srv.RegisterUS3(US3Deps{Roles: authz.NewRoles(u.ms, az, authz.NewEscalation(az), aw), Registry: authz.NewRegistry(u.ms, az, aw)})

	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	// Tenant admins cannot use operator endpoints.
	if w, out := u.call("GET", "/api/v1/operator/tenants", "", owner); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("%d %v", w.Code, out)
	}
	opw, out := u.call("POST", "/api/v1/signin", `{"tenant":"platform","email":"ops@x.test","password":"correct horse battery"}`)
	op := sessionCookie(opw)
	if opw.Code != 200 || out["mfa_setup_required"] != true {
		t.Fatalf("operators must be asked to enrol: %d %v", opw.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/session", "", op); w.Code != 200 || out["operator"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, out := u.call("POST", "/api/v1/operator/tenants", `{"slug":"globex","display_name":"Globex","owner_email":"owner@globex.test"}`, op)
	if w.Code != 201 || out["invitation_id"] == "" {
		t.Fatalf("%d %v", w.Code, out)
	}
	globex := out["tenant"].(map[string]any)["id"].(string)
	if w, _ := u.call("POST", "/api/v1/operator/tenants", `{"slug":"Bad Slug","display_name":"x","owner_email":"o@x"}`, op); w.Code != 400 {
		t.Fatal("bad slug")
	}
	w, _ = u.call("GET", "/api/v1/operator/tenants", "", op)
	var list struct{ Items []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != 200 || len(list.Items) != 3 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Tenants page (operator only) and one tenant by id.
	tp := u.page(t, "/api/v1/operator/tenants?page_size=2&sort=slug", op)
	if tp.Total != 3 || len(tp.Items) != 2 || tp.Items[0]["slug"] != "acme" || tp.Items[1]["slug"] != "globex" {
		t.Fatalf("tenants page %+v", tp)
	}
	if w, out := u.call("GET", "/api/v1/operator/tenants/"+globex, "", op); w.Code != 200 || out["slug"] != "globex" {
		t.Fatalf("get tenant → %d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/operator/tenants/"+globex, "", owner); w.Code != 403 {
		t.Fatalf("get tenant as tenant admin → %d", w.Code)
	}
	if w, _ := u.call("GET", "/api/v1/operator/tenants/nope", "", op); w.Code != 404 {
		t.Fatalf("unknown tenant → %d", w.Code)
	}
	u.refused(t, "/api/v1/operator/tenants?sort=policy", "sort", "policy", op)
	// Policy: owner reads/updates their own; invalid refused.
	if w, out := u.call("GET", "/api/v1/admin/policy", "", owner); w.Code != 200 || out["password_min_length"].(float64) != 12 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/policy", `{"session_lifetime":"2h","idle_timeout":"30m","access_token_lifetime":"10m","password_min_length":14,"mfa_required":false,"lockout_threshold":5,"lockout_duration":"10m"}`, owner); w.Code != 200 || out["password_min_length"].(float64) != 14 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("PUT", "/api/v1/admin/policy", `{"session_lifetime":"48h"}`, owner); w.Code != 400 {
		t.Fatal("invalid policy accepted")
	}
	// Operator in globex: refused without a grant, allowed with one (audited).
	hdr := func(method, path, body string, c *http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
		r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
		r = r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.5"))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		r.Header.Set(edge.CSRFHeader, "x")
		r.Header.Set(OperatorTenantHeader, globex)
		r.AddCookie(c)
		rec := httptest.NewRecorder()
		u.srv.Handler().ServeHTTP(rec, r)
		o := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &o)
		return rec, o
	}
	if w, out := hdr("GET", "/api/v1/admin/policy", "", op); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("no grant → %d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/operator/grants", `{"tenant_id":"`+globex+`","reason":"short","duration":"1h"}`, op); w.Code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/operator/grants", `{"tenant_id":"`+globex+`","reason":"support ticket 4321","duration":"5h"}`, op); w.Code != 400 {
		t.Fatal("5h grant accepted")
	}
	if w, out := u.call("POST", "/api/v1/operator/grants", `{"tenant_id":"`+globex+`","reason":"support ticket 4321","duration":"1h"}`, op); w.Code != 201 || out["tenant_id"] != globex {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := hdr("GET", "/api/v1/admin/policy", "", op); w.Code != 200 {
		t.Fatalf("with grant → %d", w.Code)
	}
	if w, _ := hdr("GET", "/api/v1/admin/users", "", op); w.Code != 200 {
		t.Fatalf("admin users with grant → %d", w.Code)
	}
	if w, _ := hdr("GET", "/api/v1/admin/policy", "", owner); w.Code != 403 {
		t.Fatal("non-operator with header")
	}
	// Suspend → owner's session dead, sign-in refused; reactivate.
	if w, _ := u.call("POST", "/api/v1/operator/tenants/"+tid+"/suspend", "", op); w.Code != 204 {
		t.Fatal("suspend")
	}
	if w, _ := u.call("GET", "/api/v1/session", "", owner); w.Code != 401 {
		t.Fatal("session survived suspension")
	}
	if w, out := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`); w.Code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/operator/tenants/"+tid+"/reactivate", "", op); w.Code != 204 {
		t.Fatal("reactivate")
	}
	ow, _ = u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner = sessionCookie(ow)
	// Clients: confidential secret shown once; listing never includes it.
	w, out = u.call("POST", "/api/v1/admin/clients", `{"display_name":"Backend","redirect_uris":["https://svc.example.org/cb"],"public":false}`, owner)
	if w.Code != 201 || out["client_secret"] == nil || out["client_id"] == nil {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/clients", `{"display_name":"Bad","redirect_uris":["ftp://x"],"public":true}`, owner); w.Code != 400 {
		t.Fatal("bad redirect")
	}
	w, _ = u.call("GET", "/api/v1/admin/clients", "", owner)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "Backend") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// Paged (feature 032): bare array without list parameters, a page with
	// them; neither carries the secret.
	if !strings.HasPrefix(w.Body.String(), "[") {
		t.Fatalf("legacy clients must stay a bare array: %s", w.Body.String())
	}
	if _, out := u.call("POST", "/api/v1/admin/clients", `{"display_name":"alpha","redirect_uris":["https://a.example.org/cb"],"public":true}`, owner); out["client_id"] == nil {
		t.Fatalf("second client %v", out)
	}
	cp := u.page(t, "/api/v1/admin/clients?page_size=1", owner)
	if cp.Total != 2 || len(cp.Items) != 1 || cp.Items[0]["display_name"] != "alpha" || cp.Sort != "display_name" {
		t.Fatalf("clients page %+v", cp)
	}
	if w, _ := u.call("GET", "/api/v1/admin/clients?page=1", "", owner); strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("paged clients leak the secret: %s", w.Body.String())
	}
	u.refused(t, "/api/v1/admin/clients?sort=secret_hash", "sort", "secret_hash", owner)
	// Roles keep their bare array for one release; a page with list parameters.
	w, _ = u.call("GET", "/api/v1/admin/roles", "", owner)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "[") {
		t.Fatalf("legacy roles %d %s", w.Code, w.Body.String())
	}
	var all []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &all)
	rp := u.page(t, "/api/v1/admin/roles?page_size=2&sort=slug", owner)
	if rp.Total != len(all) || len(rp.Items) != 2 || rp.Sort != "slug" {
		t.Fatalf("roles page %+v (all %d)", rp, len(all))
	}
	u.refused(t, "/api/v1/admin/roles?sort=permissions", "sort", "permissions", owner)
	aw.Close()
	types := map[string]int{}
	for _, r := range u.ms.AuditRows {
		types[r.EventType]++
	}
	if types["tenant_created"] != 1 || types["operator_grant_created"] != 1 || types["operator_grant_used"] < 2 || types["tenant_suspended"] != 1 || types["client_registered"] != 2 || types["policy_updated"] != 1 {
		t.Fatalf("audit %v", types)
	}
}
