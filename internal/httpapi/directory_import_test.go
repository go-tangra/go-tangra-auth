package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/directory"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Feature 016 US2: search and import routes (contracts §A, gate D) and the
// admin users list with the imported status and directory origin.

// dirSearchWire is a SearchResult in its wire form: one entry per preview
// status (contracts §A SearchResult).
const dirSearchWire = `{"items":[` +
	`{"uid":"uid-alice","dn":"CN=Alice,OU=People,DC=example,DC=test","email":"alice@example.test","display_name":"Alice Liddell","first_name":"Alice","last_name":"Liddell","status":"new","user_id":null,"reason":null},` +
	`{"uid":"uid-bob","dn":"CN=Bob,OU=People,DC=example,DC=test","email":"bob@example.test","display_name":"Bob","first_name":"Bob","last_name":"","status":"existing_user","user_id":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4a01","reason":null},` +
	`{"uid":"uid-carol","dn":"CN=Carol,OU=People,DC=example,DC=test","email":"carol@example.test","display_name":"Carol","first_name":"","last_name":"","status":"imported","user_id":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4a02","reason":null},` +
	`{"uid":"uid-dave","dn":"CN=Dave,OU=People,DC=example,DC=test","email":null,"display_name":"Dave","first_name":"","last_name":"","status":"invalid","user_id":null,"reason":"no_email"}` +
	`],"truncated":true,"out_of_scope":2,"effective_filter":"(&(objectClass=user)(department=Eng))"}`

// dirImportWire is a partial-success ImportResult in its wire form.
const dirImportWire = `{` +
	`"created":[{"uid":"uid-alice","user_id":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4a03"}],` +
	`"updated":[{"uid":"uid-carol","user_id":"0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4a02"}],` +
	`"skipped":[{"uid":"uid-dave","reason":"no_email"},{"uid":"uid-gone","reason":"not_found_in_directory"}],` +
	`"failed":[{"uid":"uid-erin","reason":"timeout"}]}`

func dirSearchResult(t *testing.T, raw string) directory.SearchResult {
	t.Helper()
	var r directory.SearchResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("directory.SearchResult must decode its own wire form: %v", err)
	}
	return r
}

func dirImportResult(t *testing.T, raw string) directory.ImportResult {
	t.Helper()
	var r directory.ImportResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("directory.ImportResult must decode its own wire form: %v", err)
	}
	return r
}

// last attaches search/import arguments to the call record just appended.
func (f *fakeDirectories) last(fill func(*dirCall)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fill(&f.calls[len(f.calls)-1])
}

func (f *fakeDirectories) Search(_ context.Context, a tenantctx.Actor, tenantID, connID string, q directory.SearchRequest) (directory.SearchResult, error) {
	err := f.record("search", a, tenantID, connID, directory.Input{})
	f.last(func(c *dirCall) { c.Search = q })
	if err != nil {
		return directory.SearchResult{}, err
	}
	if _, err := f.lookup(tenantID, connID); err != nil {
		return directory.SearchResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.found, nil
}

func (f *fakeDirectories) Import(_ context.Context, a tenantctx.Actor, tenantID, connID string, uids []string) (directory.ImportResult, error) {
	err := f.record("import", a, tenantID, connID, directory.Input{})
	f.last(func(c *dirCall) { c.UIDs = slices.Clone(uids) })
	if err != nil {
		return directory.ImportResult{}, err
	}
	if _, err := f.lookup(tenantID, connID); err != nil {
		return directory.ImportResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.imp, nil
}

// jsonEqual compares a response body with the expected wire form.
func jsonEqual(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%s: body is not JSON: %q", what, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s:\n got %s\nwant %s", what, got, want)
	}
}

func TestDirectorySearchRoute(t *testing.T) {
	h := newDirHarness(t, true)
	path := "/api/v1/admin/directories/" + dirConnA + "/search"

	// 200 SearchResult exactly as the service produced it; the request is
	// handed over field by field with the id from the path.
	w, _ := h.call("POST", path, `{"filter":"(department=Eng)","base":"OU=Eng,OU=People,DC=example,DC=test","scope":"one"}`, "admin", true)
	if w.Code != 200 {
		t.Fatalf("search → %d %s", w.Code, w.Body.String())
	}
	jsonEqual(t, "search", w.Body.Bytes(), dirSearchWire)
	calls := h.svc.reset()
	want := directory.SearchRequest{Filter: "(department=Eng)", Base: "OU=Eng,OU=People,DC=example,DC=test", Scope: "one"}
	if len(calls) != 1 || calls[0].Op != "search" || calls[0].ID != dirConnA || calls[0].TenantID != tid || calls[0].Search != want {
		t.Fatalf("search calls %v %+v", dirOps(calls), calls)
	}

	// Every field is optional: {} searches the whole connection base.
	if w, _ := h.call("POST", path, `{}`, "admin", true); w.Code != 200 {
		t.Fatalf("empty search → %d %s", w.Code, w.Body.String())
	}
	if calls := h.svc.reset(); len(calls) != 1 || calls[0].Search != (directory.SearchRequest{}) {
		t.Fatalf("empty search calls %+v", calls)
	}

	// An empty result still carries an items array, never null.
	h.svc.found = dirSearchResult(t, `{"items":[],"truncated":false,"out_of_scope":0,"effective_filter":"(&(objectClass=user)(objectClass=*))"}`)
	w, out := h.call("POST", path, `{"filter":"(cn=nobody)"}`, "admin", true)
	if items, ok := out["items"].([]any); w.Code != 200 || !ok || len(items) != 0 || out["truncated"] != false {
		t.Fatalf("empty result → %d %s", w.Code, w.Body.String())
	}
	h.svc.reset()

	// Bodies outside the contract never reach the service.
	for _, body := range []string{
		`{`,
		`{"filter":"(cn=a)","bogus":1}`,
		`{"scope":"base"}`,
		`{"scope":"children"}`,
		`{"filter":42}`,
		`{"base":"` + strings.Repeat("a", 1025) + `"}`,
	} {
		if w, _ := h.call("POST", path, body, "admin", true); w.Code != 400 {
			t.Fatalf("search body %.40q → %d %s", body, w.Code, w.Body.String())
		}
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatalf("invalid search bodies reached the service: %v", dirOps(calls))
	}

	// Unknown, malformed and other-tenant ids → 404.
	for _, id := range []string{dirMissing, dirConnB, "not-a-uuid"} {
		if w, out := h.call("POST", "/api/v1/admin/directories/"+id+"/search", `{}`, "admin", true); w.Code != 404 || out["reason"] != "not_found" || len(out) != 1 {
			t.Fatalf("search %s → %d %v", id, w.Code, out)
		}
	}
	for _, c := range h.svc.reset() {
		if c.TenantID != tid {
			t.Fatalf("search asked in tenant %q", c.TenantID)
		}
	}
}

func TestDirectorySearchErrors(t *testing.T) {
	h := newDirHarness(t, true)
	path := "/api/v1/admin/directories/" + dirConnA + "/search"
	leak := fmt.Errorf("ldap: LDAP Result Code 32 \"No Such Object\": 0000208D: NameErr: DSID-03100241, best match of: 'DC=example,DC=test' password %s", dirSecret)
	cases := []struct {
		err    error
		status int
		reason string
	}{
		{ldapdir.ErrInvalidFilter, 400, "invalid_filter"},
		{ldapdir.ErrInvalidBase, 400, "invalid_base"},
		{fmt.Errorf("scope: %w", ldapdir.ErrInvalidBase), 400, "invalid_base"},
		{directory.ErrValidation, 400, "validation_failed"},
		{directory.ErrRateLimited, 429, "rate_limited"},
		{ldapdir.ErrUnreachable, 502, "unreachable"},
		{ldapdir.ErrTLS, 502, "tls_failed"},
		{ldapdir.ErrInvalidCredentials, 502, "invalid_credentials"},
		{ldapdir.ErrDirectory, 502, "directory_error"},
		{&ldapdir.DirectoryError{Code: 32}, 502, "directory_error"},
		{fmt.Errorf("search: %w", ldapdir.ErrTimeout), 504, "timeout"},
		{ldapdir.ErrTimeout, 504, "timeout"},
		{directory.ErrNotFound, 404, "not_found"},
		{tenantctx.ErrCrossTenant, 404, "not_found"},
		{leak, 500, "internal"},
	}
	for _, c := range cases {
		h.svc.setErr(c.err)
		w, out := h.call("POST", path, `{"filter":"(cn=a)"}`, "owner", true)
		if w.Code != c.status || out["reason"] != c.reason || len(out) != 1 {
			t.Fatalf("search with %q → %d %s, want %d %s", ldapdir.Reason(c.err), w.Code, w.Body.String(), c.status, c.reason)
		}
		assertNoSecret(t, c.reason, w.Body.Bytes())
		if strings.Contains(w.Body.String(), "DSID") || strings.Contains(w.Body.String(), "DC=example") {
			t.Fatalf("server text leaked: %s", w.Body.String())
		}
	}

	// A filter the parser refused carries the parser's position message
	// (built only from what the caller typed) next to the closed reason.
	for _, err := range []error{
		&ldapdir.FilterError{Detail: "unexpected end of filter"},
		fmt.Errorf("compile: %w", &ldapdir.FilterError{Detail: "filter does not start with an '(' at position 0"}),
	} {
		var fe *ldapdir.FilterError
		if !errors.As(err, &fe) {
			t.Fatal("fixture is not a FilterError")
		}
		h.svc.setErr(err)
		w, out := h.call("POST", path, `{"filter":"(cn=a"}`, "owner", true)
		if w.Code != 400 || out["reason"] != "invalid_filter" || out["message"] != fe.Detail || len(out) != 2 {
			t.Fatalf("filter error → %d %s, want 400 invalid_filter with message %q", w.Code, w.Body.String(), fe.Detail)
		}
	}
	// No other refusal carries a message.
	h.svc.setErr(ldapdir.ErrInvalidBase)
	if _, out := h.call("POST", path, `{"base":"DC=evilexample,DC=test"}`, "owner", true); out["message"] != nil {
		t.Fatalf("invalid_base must not carry a message: %v", out)
	}
}

func dirUIDsBody(uids ...string) string {
	raw, _ := json.Marshal(map[string]any{"uids": uids})
	return string(raw)
}

func TestDirectoryImportRoute(t *testing.T) {
	h := newDirHarness(t, true)
	path := "/api/v1/admin/directories/" + dirConnA + "/import"

	// Partial success is still 200: created, updated, skipped and failed
	// entries come back side by side exactly as the service reported them.
	w, _ := h.call("POST", path, dirUIDsBody("uid-alice", "uid-carol", "uid-dave", "uid-gone", "uid-erin"), "admin", true)
	if w.Code != 200 {
		t.Fatalf("import → %d %s", w.Code, w.Body.String())
	}
	jsonEqual(t, "import", w.Body.Bytes(), dirImportWire)
	calls := h.svc.reset()
	if len(calls) != 1 || calls[0].Op != "import" || calls[0].ID != dirConnA || calls[0].TenantID != tid || calls[0].Actor.UserID != "u-admin" ||
		!slices.Equal(calls[0].UIDs, []string{"uid-alice", "uid-carol", "uid-dave", "uid-gone", "uid-erin"}) {
		t.Fatalf("import calls %v %+v", dirOps(calls), calls)
	}

	// The uids are passed verbatim: filter metacharacters are the service's
	// job to escape, not the handler's to rewrite or refuse.
	odd := []string{"*", `a)(|(uid=*)`, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"}
	if w, _ := h.call("POST", path, dirUIDsBody(odd...), "admin", true); w.Code != 200 {
		t.Fatalf("import odd uids → %d %s", w.Code, w.Body.String())
	}
	if calls := h.svc.reset(); len(calls) != 1 || !slices.Equal(calls[0].UIDs, odd) {
		t.Fatalf("odd uids not passed verbatim: %+v", calls)
	}

	// Nothing imported still renders four arrays, never null.
	h.svc.imp = directory.ImportResult{}
	w, out := h.call("POST", path, dirUIDsBody("uid-x"), "admin", true)
	if w.Code != 200 {
		t.Fatalf("empty import → %d %s", w.Code, w.Body.String())
	}
	for _, k := range []string{"created", "updated", "skipped", "failed"} {
		if a, ok := out[k].([]any); !ok || len(a) != 0 {
			t.Fatalf("empty import %s = %v, want []", k, out[k])
		}
	}
	h.svc.reset()

	// 1..500 unique uids in a closed body; anything else is refused before
	// the service.
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("uid-%03d", i)
	}
	for _, body := range []string{
		`{`,
		`{}`,
		`{"uids":[]}`,
		`{"uids":"uid-alice"}`,
		`{"uids":[1]}`,
		`{"uids":["uid-alice"],"bogus":1}`,
		dirUIDsBody("uid-alice", "uid-alice"),
		dirUIDsBody(many...),
	} {
		if w, _ := h.call("POST", path, body, "admin", true); w.Code != 400 {
			t.Fatalf("import body %.40q → %d %s", body, w.Code, w.Body.String())
		}
	}
	if calls := h.svc.reset(); len(calls) != 0 {
		t.Fatalf("invalid import bodies reached the service: %v", dirOps(calls))
	}
	// Exactly 500 is allowed.
	if w, _ := h.call("POST", path, dirUIDsBody(many[:500]...), "admin", true); w.Code != 200 {
		t.Fatalf("500 uids → %d %s", w.Code, w.Body.String())
	}
	if calls := h.svc.reset(); len(calls) != 1 || len(calls[0].UIDs) != 500 {
		t.Fatal("500 uids not handed to the service")
	}

	// Unknown, malformed and other-tenant ids → 404.
	for _, id := range []string{dirMissing, dirConnB, "not-a-uuid"} {
		if w, out := h.call("POST", "/api/v1/admin/directories/"+id+"/import", dirUIDsBody("uid-alice"), "admin", true); w.Code != 404 || out["reason"] != "not_found" || len(out) != 1 {
			t.Fatalf("import %s → %d %v", id, w.Code, out)
		}
	}
	h.svc.reset()
}

func TestDirectoryImportErrors(t *testing.T) {
	h := newDirHarness(t, true)
	path := "/api/v1/admin/directories/" + dirConnA + "/import"
	// Whole-request failures: the directory could not be used at all, so
	// nothing was imported and no ImportResult is returned.
	cases := []struct {
		err    error
		status int
		reason string
	}{
		{directory.ErrValidation, 400, "validation_failed"},
		{ldapdir.ErrUnreachable, 502, "unreachable"},
		{ldapdir.ErrTLS, 502, "tls_failed"},
		{ldapdir.ErrInvalidCredentials, 502, "invalid_credentials"},
		{&ldapdir.DirectoryError{Code: 1}, 502, "directory_error"},
		{ldapdir.ErrTimeout, 504, "timeout"},
		{directory.ErrRateLimited, 429, "rate_limited"},
		{store.ErrNotFound, 404, "not_found"},
		{tenantctx.ErrCrossTenant, 404, "not_found"},
		{fmt.Errorf("bind %s: boom", dirSecret), 500, "internal"},
	}
	for _, c := range cases {
		h.svc.setErr(c.err)
		w, out := h.call("POST", path, dirUIDsBody("uid-alice"), "owner", true)
		if w.Code != c.status || out["reason"] != c.reason || len(out) != 1 {
			t.Fatalf("import with %q → %d %s, want %d %s", ldapdir.Reason(c.err), w.Code, w.Body.String(), c.status, c.reason)
		}
		assertNoSecret(t, c.reason, w.Body.Bytes())
	}
}

// TestDirectoryImportGate: search and import sit behind gate D and CSRF like
// the connection routes (the shared route table covers them too); a custom
// role holding directory:manage may import, one without it may not.
func TestDirectoryImportGate(t *testing.T) {
	h := newDirHarness(t, true)
	for _, rt := range []dirRoute{
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/search", `{"filter":"(cn=a)"}`},
		{"POST", "/api/v1/admin/directories/" + dirConnA + "/import", dirUIDsBody("uid-alice")},
	} {
		if w, out := h.call(rt.method, rt.path, rt.body, "", true); w.Code != 401 || out["reason"] != "unauthenticated" {
			t.Fatalf("anonymous %s → %d %v", rt.path, w.Code, out)
		}
		for _, who := range []string{"member", "auditor"} {
			if w, out := h.call(rt.method, rt.path, rt.body, who, true); w.Code != 403 || out["reason"] != "forbidden" {
				t.Fatalf("%s %s → %d %v", who, rt.path, w.Code, out)
			}
		}
		if w, _ := h.call(rt.method, rt.path, rt.body, "owner", false); w.Code/100 != 4 {
			t.Fatalf("%s without X-CSRF-Token → %d", rt.path, w.Code)
		}
		if calls := h.svc.reset(); len(calls) != 0 {
			t.Fatalf("%s: refused requests reached the service: %v", rt.path, dirOps(calls))
		}
		if w, _ := h.call(rt.method, rt.path, rt.body, "importer", true); w.Code != 200 {
			t.Fatalf("importer %s → %d %s", rt.path, w.Code, w.Body.String())
		}
		if calls := h.svc.reset(); len(calls) != 1 || calls[0].Actor.UserID != "u-imp" {
			t.Fatalf("%s: importer calls %v", rt.path, dirOps(calls))
		}
	}
	// Disabled feature: 404 before anything else.
	off := newDirHarness(t, false)
	for _, p := range []string{"/search", "/import"} {
		body := `{}`
		if p == "/import" {
			body = dirUIDsBody("uid-alice")
		}
		if w, out := off.call("POST", "/api/v1/admin/directories/"+dirConnA+p, body, "owner", true); w.Code != 404 || out["reason"] != "not_found" {
			t.Fatalf("disabled %s → %d %v", p, w.Code, out)
		}
	}
}

// TestAdminUsersListImported: GET /api/v1/admin/users?status=imported lists
// imported users with their directory origin and no pending invitation;
// other users carry directory: null, invited ones their invitation id.
func TestAdminUsersListImported(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	ctx := context.Background()
	const (
		connID  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d01"
		uImp    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d11"
		uOrphan = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d12" // its connection was deleted
		uInv    = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d13"
		invID   = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d21"
	)
	imported := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	if err := u.ms.InsertDirectoryConnection(ctx, store.DirectoryConnection{
		ID: connID, TenantID: tid, Name: "Corp AD", Kind: "active_directory", URL: "ldaps://ldap.example.test", TLSMode: "ldaps",
		BindDN: "CN=svc,DC=example,DC=test", BindPasswordEnc: []byte("sealed"), BaseDN: "OU=People,DC=example,DC=test",
		AttrUID: "objectGUID", AttrEmail: "mail", SizeLimit: 500, TimeLimitSeconds: 15,
	}); err != nil {
		t.Fatal(err)
	}
	u.ms.AddUser(store.User{ID: uImp, TenantID: tid, Email: "imp@x.test", DisplayName: "Imp Orted", FirstName: "Imp", LastName: "Orted", Status: "imported"})
	u.ms.AddUser(store.User{ID: uOrphan, TenantID: tid, Email: "orphan@x.test", DisplayName: "Orphan", Status: "imported"})
	u.ms.AddUser(store.User{ID: uInv, TenantID: tid, Email: "inv@x.test", DisplayName: "Inv", Status: "invited"})
	cid := connID
	for _, l := range []store.DirectoryLink{
		{UserID: uImp, TenantID: tid, ConnectionID: &cid, ConnectionName: "Corp AD", DirectoryUID: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
			DirectoryDN: "CN=Imp Orted,OU=People,DC=example,DC=test", FirstImportedAt: imported, LastImportedAt: imported},
		{UserID: uOrphan, TenantID: tid, ConnectionName: "Old LDAP", DirectoryUID: "uid-orphan",
			DirectoryDN: "uid=orphan,ou=People,dc=old,dc=test", FirstImportedAt: imported, LastImportedAt: imported},
	} {
		if err := u.ms.UpsertLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	u.ms.Invitations[invID] = store.Invitation{ID: invID, TenantID: tid, Email: "inv@x.test", TokenHash: "h", ExpiresAt: imported.Add(72 * time.Hour)}

	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)

	type item = map[string]any
	list := func(query string) map[string]item {
		t.Helper()
		w, out := u.call("GET", "/api/v1/admin/users"+query, "", owner)
		items, ok := out["items"].([]any)
		if w.Code != 200 || !ok {
			t.Fatalf("list %s → %d %s", query, w.Code, w.Body.String())
		}
		by := map[string]item{}
		for _, x := range items {
			m := x.(item)
			by[m["id"].(string)] = m
		}
		return by
	}

	by := list("?status=imported")
	if len(by) != 2 || by[uImp] == nil || by[uOrphan] == nil {
		t.Fatalf("status=imported → %v", by)
	}
	imp := by[uImp]
	if imp["status"] != "imported" || imp["email"] != "imp@x.test" || imp["first_name"] != "Imp" {
		t.Fatalf("imported item %v", imp)
	}
	if v, ok := imp["invitation_id"]; !ok || v != nil {
		t.Fatalf("imported item must carry invitation_id: null, got %v (present %v)", v, ok)
	}
	if roles, _ := imp["roles"].([]any); len(roles) != 0 {
		t.Fatalf("imported user has roles %v", roles)
	}
	raw, _ := json.Marshal(imp["directory"])
	jsonEqual(t, "directory origin", raw,
		`{"connection_id":"`+connID+`","connection_name":"Corp AD","directory_uid":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","last_imported_at":"2026-09-24T10:00:00Z"}`)
	// A deleted connection keeps its name as the origin label.
	raw, _ = json.Marshal(by[uOrphan]["directory"])
	jsonEqual(t, "orphan origin", raw,
		`{"connection_id":null,"connection_name":"Old LDAP","directory_uid":"uid-orphan","last_imported_at":"2026-09-24T10:00:00Z"}`)

	// The q filter combines with the status filter.
	if by := list("?status=imported&q=orphan"); len(by) != 1 || by[uOrphan] == nil {
		t.Fatalf("status=imported&q=orphan → %v", by)
	}

	// Without the filter: every user carries both keys; only imported users
	// have an origin, only invited users a pending invitation.
	all := list("")
	if len(all) != 5 {
		t.Fatalf("unfiltered list has %d users", len(all))
	}
	for id, m := range all {
		d, hasDir := m["directory"]
		inv, hasInv := m["invitation_id"]
		if !hasDir || !hasInv {
			t.Fatalf("user %s lacks directory/invitation_id keys: %v", id, m)
		}
		switch id {
		case uImp, uOrphan:
			if d == nil || inv != nil {
				t.Fatalf("imported %s: directory %v invitation %v", id, d, inv)
			}
		case uInv:
			if d != nil || inv != invID || m["status"] != "invited" {
				t.Fatalf("invited %s: directory %v invitation %v", id, d, inv)
			}
		default:
			if d != nil || inv != nil {
				t.Fatalf("active %s: directory %v invitation %v", id, d, inv)
			}
		}
	}
	// Nothing about the directory entry beyond the origin label leaks.
	w, _ := u.call("GET", "/api/v1/admin/users?status=imported", "", owner)
	if strings.Contains(w.Body.String(), "OU=People") || strings.Contains(w.Body.String(), "sealed") {
		t.Fatalf("users list exposes directory internals: %s", w.Body.String())
	}
}
