package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/directory"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/transport/edge"
)

// Feature 016 US1: the directory connection routes (contracts §A, gate D).

const (
	dirTID2    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	dirConnA   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c01" // tenant tid
	dirConnB   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c02" // tenant dirTID2
	dirMissing = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4cff"
	// dirSecret is the bind password typed by the admin; it must never appear
	// in any response. Never print it.
	dirSecret = "S3NT1NEL-bind-pw-0f2c"
)

// Session secrets → actors.
var dirActors = map[string]tenantctx.Actor{
	"owner":    {Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tid, Roles: []string{"owner"}},
	"admin":    {Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tid, Roles: []string{"admin"}},
	"importer": {Kind: tenantctx.KindUser, UserID: "u-imp", TenantID: tid, Roles: []string{"importer"}},
	"auditor":  {Kind: tenantctx.KindUser, UserID: "u-aud", TenantID: tid, Roles: []string{"auditor"}},
	"member":   {Kind: tenantctx.KindUser, UserID: "u-mem", TenantID: tid},
	"admin2":   {Kind: tenantctx.KindUser, UserID: "u-admin2", TenantID: dirTID2, Roles: []string{"admin"}},
}

type dirSessions struct{}

func (dirSessions) Resolve(_ context.Context, secret string) (tenantctx.Actor, error) {
	if a, ok := dirActors[secret]; ok {
		return a, nil
	}
	return tenantctx.Actor{}, errors.New("no session")
}

// countingAuthz wraps the real authz client (over the in-memory FGA fake) and
// counts permission checks, so the owner/admin short-circuit is observable.
type countingAuthz struct {
	c  *authz.Client
	mu sync.Mutex
	n  int
}

func (a *countingAuthz) Allowed(ctx context.Context, tenantID, userID string, p authz.PermissionRef) (bool, error) {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
	return a.c.Allowed(ctx, tenantID, userID, p)
}

func (a *countingAuthz) calls() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

type failingAuthz struct{}

func (failingAuthz) Allowed(context.Context, string, string, authz.PermissionRef) (bool, error) {
	return false, errors.New("fga: backend unavailable at 10.0.0.9")
}

type dirCall struct {
	Op       string
	Actor    tenantctx.Actor
	TenantID string
	ID       string
	Input    directory.Input
	Search   directory.SearchRequest // search only
	UIDs     []string                // import only
}

// fakeDirectories stands in for *directory.Service: connections keyed by
// tenant, every call recorded, an optional error returned from every method.
type fakeDirectories struct {
	t     *testing.T
	mu    sync.Mutex
	conns map[string]map[string]directory.Connection // tenant → id → view
	calls []dirCall
	err   error
	test  directory.TestResult
	found directory.SearchResult // returned by Search
	imp   directory.ImportResult // returned by Import
}

func newFakeDirectories(t *testing.T) *fakeDirectories {
	f := &fakeDirectories{t: t, conns: map[string]map[string]directory.Connection{tid: {}, dirTID2: {}}}
	f.conns[tid][dirConnA] = dirView(t, dirConnA, "Corp AD", true)
	f.conns[dirTID2][dirConnB] = dirView(t, dirConnB, "Other LDAP", true)
	f.test = dirResult(t, `{"ok":true,"step":null,"reason":null,"tls":{"version":"TLS 1.3","peer_subject":"CN=ldap.example.test"},"duration_ms":12}`)
	f.found = dirSearchResult(t, dirSearchWire)
	f.imp = dirImportResult(t, dirImportWire)
	return f
}

// dirView builds a Connection from its wire form only (contracts §A), then
// deliberately offers every password-shaped key an implementation might map:
// if the view type carried one, the handler's response would leak it.
func dirView(t *testing.T, id, name string, withCA bool) directory.Connection {
	t.Helper()
	m := map[string]any{
		"id": id, "name": name, "kind": "active_directory", "url": "ldaps://ldap.example.test",
		"tls_mode": "ldaps", "allow_tls12": false, "ca_pem_set": withCA,
		"bind_dn": "CN=svc-freya,OU=Service,DC=example,DC=test", "bind_password_set": true,
		"base_dn": "OU=People,DC=example,DC=test", "base_filter": "(objectClass=user)",
		"attributes": map[string]any{"uid": "objectGUID", "email": "mail", "display_name": "displayName", "first_name": "givenName", "last_name": "sn"},
		"size_limit": 500, "time_limit_seconds": 15,
		"last_test":  map[string]any{"at": "2026-09-24T10:00:00Z", "outcome": "ok"},
		"created_at": "2026-09-24T09:00:00Z", "updated_at": "2026-09-24T09:30:00Z",
		"bind_password": dirSecret, "BindPassword": dirSecret, "password": dirSecret,
		"bind_password_enc": dirSecret, "BindPasswordEnc": []byte(dirSecret),
	}
	if withCA {
		m["ca_pem"] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c directory.Connection
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("directory.Connection must decode its own wire form: %v", err)
	}
	return c
}

func dirResult(t *testing.T, raw string) directory.TestResult {
	t.Helper()
	var r directory.TestResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("directory.TestResult must decode its own wire form: %v", err)
	}
	return r
}

func (f *fakeDirectories) record(op string, a tenantctx.Actor, tenantID, id string, in directory.Input) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dirCall{Op: op, Actor: a, TenantID: tenantID, ID: id, Input: in})
	if tenantID != a.TenantID {
		f.t.Errorf("%s: tenant %q taken from somewhere other than the actor (%q)", op, tenantID, a.TenantID)
	}
	return f.err
}

func (f *fakeDirectories) lookup(tenantID, id string) (directory.Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conns[tenantID][id]
	if !ok {
		return directory.Connection{}, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeDirectories) List(_ context.Context, a tenantctx.Actor, tenantID string) ([]directory.Connection, error) {
	if err := f.record("list", a, tenantID, "", directory.Input{}); err != nil {
		return nil, err
	}
	c, _ := f.lookup(tenantID, map[string]string{tid: dirConnA, dirTID2: dirConnB}[tenantID])
	return []directory.Connection{c}, nil
}

func (f *fakeDirectories) Get(_ context.Context, a tenantctx.Actor, tenantID, id string) (directory.Connection, error) {
	if err := f.record("get", a, tenantID, id, directory.Input{}); err != nil {
		return directory.Connection{}, err
	}
	return f.lookup(tenantID, id)
}

func (f *fakeDirectories) Create(_ context.Context, a tenantctx.Actor, tenantID string, in directory.Input) (directory.Connection, error) {
	if err := f.record("create", a, tenantID, "", in); err != nil {
		return directory.Connection{}, err
	}
	return f.lookup(tenantID, dirConnA)
}

func (f *fakeDirectories) Update(_ context.Context, a tenantctx.Actor, tenantID, id string, in directory.Input) (directory.Connection, error) {
	if err := f.record("update", a, tenantID, id, in); err != nil {
		return directory.Connection{}, err
	}
	return f.lookup(tenantID, id)
}

func (f *fakeDirectories) Remove(_ context.Context, a tenantctx.Actor, tenantID, id string) error {
	if err := f.record("remove", a, tenantID, id, directory.Input{}); err != nil {
		return err
	}
	_, err := f.lookup(tenantID, id)
	return err
}

func (f *fakeDirectories) Test(_ context.Context, a tenantctx.Actor, tenantID string, in directory.Input, connID string) (directory.TestResult, error) {
	if err := f.record("test", a, tenantID, connID, in); err != nil {
		return directory.TestResult{}, err
	}
	if connID != "" {
		if _, err := f.lookup(tenantID, connID); err != nil {
			return directory.TestResult{}, err
		}
	}
	return f.test, nil
}

// dirOps renders calls without their input (which may hold the password).
func dirOps(calls []dirCall) []string {
	out := make([]string, len(calls))
	for i := range calls {
		out[i] = calls[i].Op + " " + calls[i].TenantID + " " + calls[i].ID
	}
	return out
}

func (f *fakeDirectories) setErr(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func (f *fakeDirectories) reset() []dirCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls, f.err = nil, nil
	return c
}

type dirHarness struct {
	srv *Server
	svc *fakeDirectories
	az  *countingAuthz
}

func newDirHarness(t *testing.T, enabled bool) *dirHarness {
	t.Helper()
	fga := authz.NewFake()
	manage := authz.PermissionRef{Resource: "directory", Action: "manage"}
	// "importer" is a custom role granted directory:manage; "auditor" is not.
	if err := fga.Write(t.Context(), []authz.Tuple{
		authz.RoleTenantTuple(tid, "importer"), authz.RoleAssignmentTuple(tid, "importer", "u-imp"),
		authz.PermissionTenantTuple(tid, manage), authz.GrantTuple(tid, "importer", manage),
		authz.RoleTenantTuple(tid, "auditor"), authz.RoleAssignmentTuple(tid, "auditor", "u-aud"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	h := &dirHarness{svc: newFakeDirectories(t), az: &countingAuthz{c: authz.New(fga, cache.New(cache.NewMemory()), nil)}}
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	srv, err := NewHandler(rt, WithSessions(dirSessions{}))
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterDirectory(DirectoryDeps{Enabled: enabled, Directories: h.svc, Authz: h.az})
	h.srv = srv
	return h
}

// call sends a request as the session named by who ("" = anonymous) with the
// CSRF header on state-changing methods unless csrf is false.
func (h *dirHarness) call(method, path, body, who string, csrf bool) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	r = r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.5"))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf && method != http.MethodGet {
		r.Header.Set(edge.CSRFHeader, "double-submit-token")
	}
	if who != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: who})
	}
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func dirCreateBody(extra string) string {
	return `{"name":"Corp AD","kind":"active_directory","url":"ldaps://ldap.example.test","tls_mode":"ldaps",` +
		`"bind_dn":"CN=svc-freya,OU=Service,DC=example,DC=test","bind_password":"` + dirSecret + `",` +
		`"base_dn":"OU=People,DC=example,DC=test","base_filter":"(objectClass=user)"` + extra + `}`
}

type dirRoute struct{ method, path, body string }

func dirRoutes() []dirRoute {
	return []dirRoute{
		{"GET", "/api/v1/admin/directories", ""},
		{"POST", "/api/v1/admin/directories", dirCreateBody("")},
		{"GET", "/api/v1/admin/directories/" + dirConnA, ""},
		{"PUT", "/api/v1/admin/directories/" + dirConnA, `{"name":"Renamed"}`},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/remove", ""},
		{"POST", "/api/v1/admin/directories/test", dirCreateBody("")},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/test", ""},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/search", `{"filter":"(department=Eng)"}`},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/import", `{"uids":["uid-alice"]}`},
	}
}

// assertNoSecret fails when a response body carries the bind password or any
// password-bearing key other than the bind_password_set flag.
func assertNoSecret(t *testing.T, what string, body []byte) {
	t.Helper()
	if strings.Contains(string(body), dirSecret) {
		t.Fatalf("%s: response contains the bind password", what)
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if strings.Contains(strings.ToLower(k), "password") && k != "bind_password_set" {
					t.Fatalf("%s: response carries key %q", what, k)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
}

func TestDirectoryRequirePermission(t *testing.T) {
	h := newDirHarness(t, true)
	for _, rt := range dirRoutes() {
		name := rt.method + " " + rt.path
		// Unauthenticated → 401, before any service call.
		if w, out := h.call(rt.method, rt.path, rt.body, "", true); w.Code != 401 || out["reason"] != "unauthenticated" {
			t.Fatalf("anonymous %s → %d %v", name, w.Code, out)
		}
		// A plain member and a custom role without the grant → 403.
		for _, who := range []string{"member", "auditor"} {
			if w, out := h.call(rt.method, rt.path, rt.body, who, true); w.Code != 403 || out["reason"] != "forbidden" {
				t.Fatalf("%s %s → %d %v", who, name, w.Code, out)
			}
		}
		if calls := h.svc.reset(); len(calls) != 0 {
			t.Fatalf("%s: refused callers reached the service: %v", name, dirOps(calls))
		}
		// Owner and admin are allowed by their built-in role without an FGA
		// round trip; the custom role is allowed through its FGA grant.
		before := h.az.calls()
		for _, who := range []string{"owner", "admin"} {
			if w, _ := h.call(rt.method, rt.path, rt.body, who, true); w.Code/100 != 2 {
				t.Fatalf("%s %s → %d %s", who, name, w.Code, w.Body.String())
			}
		}
		if h.az.calls() != before {
			t.Fatalf("%s: owner/admin must not need a permission check", name)
		}
		if w, _ := h.call(rt.method, rt.path, rt.body, "importer", true); w.Code/100 != 2 {
			t.Fatalf("importer %s → %d %s", name, w.Code, w.Body.String())
		}
		if h.az.calls() == before {
			t.Fatalf("%s: custom role allowed without consulting authz", name)
		}
		calls := h.svc.reset()
		if len(calls) != 3 {
			t.Fatalf("%s: %d service calls, want 3", name, len(calls))
		}
		for i := range calls {
			if calls[i].TenantID != tid {
				t.Fatalf("%s: tenant %q", name, calls[i].TenantID)
			}
		}
	}
}

func TestDirectoryRequirePermissionFailsClosed(t *testing.T) {
	h := newDirHarness(t, true)
	rt := testrt.New(t, testutil.MustCA("example.org"), "auth")
	srv, err := NewHandler(rt, WithSessions(dirSessions{}))
	if err != nil {
		t.Fatal(err)
	}
	srv.RegisterDirectory(DirectoryDeps{Enabled: true, Directories: h.svc, Authz: failingAuthz{}})
	h.srv = srv
	w, _ := h.call("GET", "/api/v1/admin/directories", "", "importer", true)
	if w.Code/100 == 2 || strings.Contains(w.Body.String(), "10.0.0.9") {
		t.Fatalf("authz failure must refuse without detail: %d %s", w.Code, w.Body.String())
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatal("service reached after an authz failure")
	}
	// The built-in roles still work when FGA is down.
	if w, _ := h.call("GET", "/api/v1/admin/directories", "", "owner", true); w.Code != 200 {
		t.Fatalf("owner → %d", w.Code)
	}
}

func TestDirectoryCSRFRequiredOnMutations(t *testing.T) {
	h := newDirHarness(t, true)
	for _, rt := range dirRoutes() {
		if rt.method == http.MethodGet {
			continue
		}
		w, _ := h.call(rt.method, rt.path, rt.body, "owner", false)
		if w.Code/100 != 4 {
			t.Fatalf("%s %s without X-CSRF-Token → %d", rt.method, rt.path, w.Code)
		}
		assertNoSecret(t, rt.path, w.Body.Bytes())
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatalf("mutations without CSRF reached the service: %d", len(calls))
	}
	// Reads need no CSRF header.
	if w, _ := h.call("GET", "/api/v1/admin/directories", "", "owner", false); w.Code != 200 {
		t.Fatalf("list → %d", w.Code)
	}
}

func TestDirectoryRoutes(t *testing.T) {
	h := newDirHarness(t, true)

	// List.
	w, out := h.call("GET", "/api/v1/admin/directories", "", "admin", true)
	items, _ := out["items"].([]any)
	if w.Code != 200 || len(items) != 1 {
		t.Fatalf("list → %d %s", w.Code, w.Body.String())
	}
	first := items[0].(map[string]any)
	if first["id"] != dirConnA || first["name"] != "Corp AD" || first["bind_password_set"] != true {
		t.Fatalf("list item %v", first)
	}
	assertNoSecret(t, "list", w.Body.Bytes())
	h.svc.reset()

	// Create → 201 with the view; the service receives the typed input.
	w, out = h.call("POST", "/api/v1/admin/directories", dirCreateBody(`,"allow_tls12":true,"size_limit":200`), "admin", true)
	if w.Code != 201 || out["id"] != dirConnA || out["bind_password_set"] != true || out["url"] != "ldaps://ldap.example.test" {
		t.Fatalf("create → %d %s", w.Code, w.Body.String())
	}
	assertNoSecret(t, "create", w.Body.Bytes())
	calls := h.svc.reset()
	if len(calls) != 1 || calls[0].Op != "create" || calls[0].Actor.UserID != "u-admin" {
		t.Fatalf("create calls %v", dirOps(calls))
	}
	raw, _ := json.Marshal(calls[0].Input)
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["name"] != "Corp AD" || got["url"] != "ldaps://ldap.example.test" || got["base_dn"] != "OU=People,DC=example,DC=test" || got["allow_tls12"] != true {
		t.Fatal("create input not handed to the service as sent") // do not print: it holds the password
	}

	// Unknown fields and malformed bodies never reach the service.
	for _, body := range []string{dirCreateBody(`,"bogus":1`), `{`, dirCreateBody(`,"bind_password_enc":"x"`)} {
		if w, _ := h.call("POST", "/api/v1/admin/directories", body, "admin", true); w.Code != 400 {
			t.Fatalf("bad body → %d", w.Code)
		}
		assertNoSecret(t, "bad body", w.Body.Bytes())
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatal("invalid bodies reached the service")
	}

	// Get → 200 with ca_pem (public data).
	w, out = h.call("GET", "/api/v1/admin/directories/"+dirConnA, "", "admin", true)
	if w.Code != 200 || out["id"] != dirConnA || out["ca_pem"] == nil || out["ca_pem_set"] != true {
		t.Fatalf("get → %d %s", w.Code, w.Body.String())
	}
	assertNoSecret(t, "get", w.Body.Bytes())
	if w, out := h.call("GET", "/api/v1/admin/directories/"+dirMissing, "", "admin", true); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("missing → %d %v", w.Code, out)
	}

	// Update (partial) → 200; the id comes from the path.
	h.svc.reset()
	w, out = h.call("PUT", "/api/v1/admin/directories/"+dirConnA, `{"name":"Renamed","bind_password":"`+dirSecret+`"}`, "admin", true)
	if w.Code != 200 || out["id"] != dirConnA {
		t.Fatalf("update → %d %s", w.Code, w.Body.String())
	}
	assertNoSecret(t, "update", w.Body.Bytes())
	calls = h.svc.reset()
	if len(calls) != 1 || calls[0].Op != "update" || calls[0].ID != dirConnA {
		t.Fatalf("update calls %d", len(calls))
	}
	raw, _ = json.Marshal(calls[0].Input)
	got = map[string]any{}
	_ = json.Unmarshal(raw, &got)
	if got["name"] != "Renamed" {
		t.Fatal("update input not handed to the service")
	}
	if w, _ := h.call("PUT", "/api/v1/admin/directories/"+dirMissing, `{"name":"x"}`, "admin", true); w.Code != 404 {
		t.Fatalf("update missing → %d", w.Code)
	}

	// Test a saved connection → 200 TestResult; the stored settings are used
	// (no input), so last_test can be persisted by the service.
	h.svc.reset()
	w, out = h.call("POST", "/api/v1/admin/directories/"+dirConnA+"/test", "", "admin", true)
	if w.Code != 200 || out["ok"] != true || out["tls"].(map[string]any)["version"] != "TLS 1.3" {
		t.Fatalf("saved test → %d %s", w.Code, w.Body.String())
	}
	calls = h.svc.reset()
	if len(calls) != 1 || calls[0].Op != "test" || calls[0].ID != dirConnA || !reflect.ValueOf(calls[0].Input).IsZero() {
		t.Fatalf("saved test calls %d", len(calls))
	}
	if w, _ := h.call("POST", "/api/v1/admin/directories/"+dirMissing+"/test", "", "admin", true); w.Code != 404 {
		t.Fatalf("saved test missing → %d", w.Code)
	}

	// Unsaved test; a failing outcome is still 200 and carries only the
	// closed reason and the failing step.
	h.svc.test = dirResult(t, `{"ok":false,"step":"bind","reason":"invalid_credentials","tls":null,"duration_ms":7}`)
	h.svc.reset()
	w, out = h.call("POST", "/api/v1/admin/directories/test", dirCreateBody(""), "admin", true)
	if w.Code != 200 || out["ok"] != false || out["step"] != "bind" || out["reason"] != "invalid_credentials" {
		t.Fatalf("unsaved test → %d %s", w.Code, w.Body.String())
	}
	assertNoSecret(t, "unsaved test", w.Body.Bytes())
	calls = h.svc.reset()
	if len(calls) != 1 || calls[0].ID != "" || reflect.ValueOf(calls[0].Input).IsZero() {
		t.Fatalf("unsaved test calls %d", len(calls))
	}
	// connection_id (password omitted) reuses the stored password of a
	// connection in the caller's tenant.
	body := `{"name":"Corp AD","kind":"active_directory","url":"ldaps://ldap.example.test","tls_mode":"ldaps",` +
		`"bind_dn":"CN=svc-freya,OU=Service,DC=example,DC=test","base_dn":"OU=People,DC=example,DC=test","connection_id":"` + dirConnA + `"}`
	if w, _ := h.call("POST", "/api/v1/admin/directories/test", body, "admin", true); w.Code != 200 {
		t.Fatalf("test with connection_id → %d %s", w.Code, w.Body.String())
	}
	calls = h.svc.reset()
	if len(calls) != 1 || calls[0].ID != dirConnA || calls[0].TenantID != tid {
		t.Fatalf("connection_id not passed: %v", dirOps(calls))
	}

	// Remove → 204 with an empty body; twice → 404.
	w, _ = h.call("POST", "/api/v1/admin/directories/"+dirConnA+"/remove", "", "admin", true)
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("remove → %d %q", w.Code, w.Body.String())
	}
	if w, out := h.call("POST", "/api/v1/admin/directories/"+dirMissing+"/remove", "", "admin", true); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("remove missing → %d %v", w.Code, out)
	}
}

func TestDirectoryCrossTenantIsNotFound(t *testing.T) {
	h := newDirHarness(t, true)
	// Tenant 2's admin addresses tenant 1's connection: the service is asked
	// only within tenant 2 and the answer is the same 404 as an unknown id.
	for _, rt := range []dirRoute{
		{"GET", "/api/v1/admin/directories/" + dirConnA, ""},
		{"PUT", "/api/v1/admin/directories/" + dirConnA, `{"name":"x"}`},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/remove", ""},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/test", ""},
	} {
		w, out := h.call(rt.method, rt.path, rt.body, "admin2", true)
		if w.Code != 404 || out["reason"] != "not_found" || len(out) != 1 {
			t.Fatalf("admin2 %s %s → %d %v", rt.method, rt.path, w.Code, out)
		}
	}
	calls := h.svc.reset()
	for i := range calls {
		if calls[i].TenantID != dirTID2 {
			t.Fatalf("%s asked in tenant %q", calls[i].Op, calls[i].TenantID)
		}
	}
	// A service that reports the refusal as cross-tenant still answers 404.
	h.svc.setErr(tenantctx.ErrCrossTenant)
	if w, out := h.call("GET", "/api/v1/admin/directories/"+dirConnA, "", "admin2", true); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("cross-tenant → %d %v", w.Code, out)
	}
	// Tenant 2 sees only its own connection.
	h.svc.reset()
	w, out := h.call("GET", "/api/v1/admin/directories", "", "admin2", true)
	items, _ := out["items"].([]any)
	if w.Code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != dirConnB {
		t.Fatalf("admin2 list → %d %s", w.Code, w.Body.String())
	}
}

func TestDirectoryErrorReasons(t *testing.T) {
	h := newDirHarness(t, true)
	leak := fmt.Errorf("ldap: server said 80090308: LdapErr: DSID-0C09044E, data 52e, password %s", dirSecret)
	cases := []struct {
		err    error
		status int
		reason string
	}{
		{directory.ErrValidation, 400, "validation_failed"},
		{fmt.Errorf("wrapped: %w", directory.ErrValidation), 400, "validation_failed"},
		{directory.ErrInsecureTransport, 400, "insecure_transport"},
		{ldapdir.ErrInvalidURL, 400, "invalid_url"},
		{ldapdir.ErrInvalidCA, 400, "invalid_ca"},
		{ldapdir.ErrInvalidFilter, 400, "invalid_filter"},
		{ldapdir.ErrInvalidBase, 400, "invalid_base"},
		{ldapdir.ErrTargetRefused, 422, "target_refused"},
		{fmt.Errorf("check: %w", ldapdir.ErrTargetRefused), 422, "target_refused"},
		{directory.ErrDuplicate, 409, "duplicate"},
		{directory.ErrLimitReached, 409, "limit_reached"},
		{directory.ErrRateLimited, 429, "rate_limited"},
		{ldapdir.ErrUnreachable, 502, "unreachable"},
		{ldapdir.ErrTLS, 502, "tls_failed"},
		{ldapdir.ErrInvalidCredentials, 502, "invalid_credentials"},
		{&ldapdir.DirectoryError{Code: 53}, 502, "directory_error"},
		{ldapdir.ErrTimeout, 504, "timeout"},
		{store.ErrNotFound, 404, "not_found"},
		{leak, 500, "internal"},
	}
	routes := []dirRoute{
		{"POST", "/api/v1/admin/directories", dirCreateBody("")},
		{"PUT", "/api/v1/admin/directories/" + dirConnA, `{"bind_password":"` + dirSecret + `"}`},
		{"POST", "/api/v1/admin/directories/test", dirCreateBody("")},
	}
	for _, c := range cases {
		for _, rt := range routes {
			h.svc.setErr(c.err)
			w, out := h.call(rt.method, rt.path, rt.body, "owner", true)
			if w.Code != c.status || out["reason"] != c.reason || len(out) != 1 {
				t.Fatalf("%s %s with %q → %d %s, want %d %s", rt.method, rt.path, ldapdir.Reason(c.err), w.Code, w.Body.String(), c.status, c.reason)
			}
			assertNoSecret(t, c.reason, w.Body.Bytes())
			if strings.Contains(w.Body.String(), "DSID") || strings.Contains(w.Body.String(), "52e") {
				t.Fatalf("server text leaked: %s", w.Body.String())
			}
		}
	}
	// Rate limiting of a saved-connection test.
	h.svc.setErr(directory.ErrRateLimited)
	if w, out := h.call("POST", "/api/v1/admin/directories/"+dirConnA+"/test", "", "owner", true); w.Code != 429 || out["reason"] != "rate_limited" {
		t.Fatalf("saved test rate limited → %d %v", w.Code, out)
	}
}

func TestDirectoryDisabledIsNotFound(t *testing.T) {
	h := newDirHarness(t, false)
	for _, rt := range dirRoutes() {
		for _, who := range []string{"owner", "importer", ""} {
			w, out := h.call(rt.method, rt.path, rt.body, who, true)
			if w.Code != 404 || out["reason"] != "not_found" || len(out) != 1 {
				t.Fatalf("disabled %s %s as %q → %d %s", rt.method, rt.path, who, w.Code, w.Body.String())
			}
		}
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatal("disabled feature reached the service")
	}
	if h.az.calls() != 0 {
		t.Fatal("disabled feature consulted authz")
	}
}
