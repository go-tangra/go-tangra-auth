package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/invite"
	"github.com/go-freya/freya/services/auth/internal/password"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/transport/edge"
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
	aw.Close()
	types := map[string]int{}
	for _, r := range u.ms.AuditRows {
		types[r.EventType]++
	}
	if types["tenant_created"] != 1 || types["operator_grant_created"] != 1 || types["operator_grant_used"] < 2 || types["tenant_suspended"] != 1 || types["client_registered"] != 1 || types["policy_updated"] != 1 {
		t.Fatalf("audit %v", types)
	}
}
