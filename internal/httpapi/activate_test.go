package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// Feature 016 US3: activation and removal of imported users over HTTP
// (contract A, research D11). ActivateRequest ids are uuids, so the new
// fixtures use uuid user ids.
const (
	actAdmin    = "0190f7c2-6a3e-7c1a-9b2e-000000000a01" // admin, not owner
	actImporter = "0190f7c2-6a3e-7c1a-9b2e-000000000a02" // custom role holding only directory:manage
	actActive   = "0190f7c2-6a3e-7c1a-9b2e-000000000a03"
	actImp1     = "0190f7c2-6a3e-7c1a-9b2e-000000000b01"
	actImp2     = "0190f7c2-6a3e-7c1a-9b2e-000000000b02"
	actImp3     = "0190f7c2-6a3e-7c1a-9b2e-000000000b03"
	actImp4     = "0190f7c2-6a3e-7c1a-9b2e-000000000b04"
	actImp5     = "0190f7c2-6a3e-7c1a-9b2e-000000000b05"
	actOther    = "0190f7c2-6a3e-7c1a-9b2e-000000000c01" // imported, other tenant
	actUnknown  = "0190f7c2-6a3e-7c1a-9b2e-000000000d01"
	actTenant2  = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c98"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type actHarness struct {
	*us1
	aw                             *audit.Writer
	owner, admin, member, importer *http.Cookie
}

func newActHarness(t *testing.T) *actHarness {
	t.Helper()
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	t.Cleanup(aw.Close)
	ctx := context.Background()
	h, _ := crypto.HashPassword("correct horse battery", crypto.DefaultParams)
	u.ms.AddRole(store.Role{ID: "r-importer", TenantID: tid, Slug: "importer"})
	u.ms.RolePerms["r-importer"] = [][2]string{{"directory", "manage"}}
	u.ms.AddUser(store.User{ID: actAdmin, TenantID: tid, Email: "adm@x.test", DisplayName: "Adm", Status: "active", PasswordHash: &h})
	_ = u.ms.ReplaceBindings(ctx, tid, actAdmin, "", []string{"r-admin"})
	u.ms.AddUser(store.User{ID: actImporter, TenantID: tid, Email: "imp-role@x.test", DisplayName: "Importer", Status: "active", PasswordHash: &h})
	_ = u.ms.ReplaceBindings(ctx, tid, actImporter, "", []string{"r-importer"})
	u.ms.AddUser(store.User{ID: actActive, TenantID: tid, Email: "act@x.test", DisplayName: "Act", Status: "active"})
	for i, id := range []string{actImp1, actImp2, actImp3, actImp4, actImp5} {
		n := i + 1
		u.ms.AddUser(store.User{ID: id, TenantID: tid, Email: fmt.Sprintf("imp%d@x.test", n), FirstName: "Imp", LastName: fmt.Sprint(n),
			DisplayName: fmt.Sprintf("Imp %d", n), Status: "imported"})
	}
	u.ms.AddTenant(store.Tenant{ID: actTenant2, Slug: "other", DisplayName: "Other", Status: "active", Kind: "customer"})
	u.ms.AddUser(store.User{ID: actOther, TenantID: actTenant2, Email: "imp1@x.test", Status: "imported"})

	a := &actHarness{us1: u, aw: aw}
	signin := func(addr string) *http.Cookie {
		w, out := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"`+addr+`","password":"correct horse battery"}`)
		c := sessionCookie(w)
		if w.Code != 200 || c == nil {
			t.Fatalf("sign-in %s → %d %v", addr, w.Code, out)
		}
		return c
	}
	a.owner, a.admin, a.member, a.importer = signin("alice@x.test"), signin("adm@x.test"), signin("bob@x.test"), signin("imp-role@x.test")
	return a
}

// callNoCSRF sends a state-changing request without the X-CSRF-Token header.
func (a *actHarness) callNoCSRF(method, path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	r = r.WithContext(edge.WithClientIP(r.Context(), "203.0.113.5"))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.AddCookie(c)
	w := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(w, r)
	return w
}

func (a *actHarness) status(t *testing.T, tenantID, uid string) string {
	t.Helper()
	u, err := a.ms.User(context.Background(), tenantID, uid)
	if errors.Is(err, store.ErrNotFound) {
		return "<deleted>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return u.Status
}

// invitationsFor counts the invitations addressed to addr in the test tenant.
func (a *actHarness) invitationsFor(addr string) []store.Invitation {
	var out []store.Invitation
	for id := range a.ms.Invitations {
		if inv := a.ms.Invitations[id]; inv.TenantID == tid && inv.Email == addr {
			out = append(out, inv)
		}
	}
	return out
}

func activateBody(ids []string, extra string) string {
	return `{"user_ids":["` + strings.Join(ids, `","`) + `"]` + extra + `}`
}

func TestActivateGate(t *testing.T) {
	a := newActHarness(t)
	body := activateBody([]string{actImp1}, "")
	// The invitation gate: a plain member and a custom role holding only
	// directory:manage are refused; nothing is written.
	for name, c := range map[string]*http.Cookie{"member": a.member, "directory:manage only": a.importer} {
		if w, out := a.call("POST", "/api/v1/admin/users/activate", body, c); w.Code != 403 || out["reason"] != "forbidden" {
			t.Fatalf("%s → %d %v", name, w.Code, out)
		}
	}
	if w, _ := a.call("POST", "/api/v1/admin/users/activate", body); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	// CSRF is required before anything happens.
	if w := a.callNoCSRF("POST", "/api/v1/admin/users/activate", body, a.owner); w.Code/100 != 4 {
		t.Fatalf("no CSRF → %d", w.Code)
	}
	if got := a.status(t, tid, actImp1); got != "imported" {
		t.Fatalf("refused requests changed the status to %q", got)
	}
	if n := len(a.ms.Invitations); n != 0 || len(a.ms.Outbox) != 0 {
		t.Fatalf("refused requests created %d invitations, %d outbox rows", n, len(a.ms.Outbox))
	}
	// Owner and admin both pass the gate.
	for name, c := range map[string]*http.Cookie{"owner": a.owner, "admin": a.admin} {
		id := actImp1
		if name == "admin" {
			id = actImp2
		}
		w, out := a.call("POST", "/api/v1/admin/users/activate", activateBody([]string{id}, ""), c)
		if w.Code != 200 {
			t.Fatalf("%s → %d %v", name, w.Code, out)
		}
		if got := a.status(t, tid, id); got != "invited" {
			t.Fatalf("%s: status %q", name, got)
		}
	}
}

func TestActivateValidation(t *testing.T) {
	a := newActHarness(t)
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("0190f7c2-6a3e-7c1a-9b2e-%012d", i)
	}
	groups := make([]string, 51)
	for i := range groups {
		groups[i] = fmt.Sprintf("0190f7c2-6a3e-7c1a-9b2f-%012d", i)
	}
	for name, body := range map[string]string{
		"empty body":     `{}`,
		"no ids":         `{"user_ids":[]}`,
		"over 100":       activateBody(many, ""),
		"duplicates":     activateBody([]string{actImp1, actImp1}, ""),
		"unknown field":  activateBody([]string{actImp1}, `,"email":"x@x.test"`),
		"over 50 groups": activateBody([]string{actImp1}, `,"group_ids":["`+strings.Join(groups, `","`)+`"]`),
	} {
		if w, out := a.call("POST", "/api/v1/admin/users/activate", body, a.owner); w.Code != 400 || out["reason"] != "validation_failed" {
			t.Fatalf("%s → %d %v", name, w.Code, out)
		}
	}
	if w, out := a.call("POST", "/api/v1/admin/users/activate", `{"user_ids":`, a.owner); w.Code != 400 || out["reason"] != "malformed_body" {
		t.Fatalf("malformed → %d %v", w.Code, out)
	}
	if got := a.status(t, tid, actImp1); got != "imported" || len(a.ms.Invitations) != 0 {
		t.Fatalf("invalid requests changed state: %q, %d invitations", got, len(a.ms.Invitations))
	}
}

func TestActivateResults(t *testing.T) {
	a := newActHarness(t)
	ids := []string{actImp1, actImp2, actActive, actUnknown, actOther}
	w, out := a.call("POST", "/api/v1/admin/users/activate", activateBody(ids, ""), a.owner)
	if w.Code != 200 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if len(out) != 1 {
		t.Fatalf("ActivateResult has only items: %v", out)
	}
	raw, _ := out["items"].([]any)
	if len(raw) != len(ids) {
		t.Fatalf("want one item per requested id, got %v", out["items"])
	}
	items := map[string]map[string]any{}
	for _, r := range raw {
		it, _ := r.(map[string]any)
		if len(it) != 4 {
			t.Fatalf("item must carry exactly user_id, outcome, invitation_id, reason: %v", it)
		}
		for _, k := range []string{"user_id", "outcome", "invitation_id", "reason"} {
			if _, ok := it[k]; !ok {
				t.Fatalf("item without %s: %v", k, it)
			}
		}
		items[it["user_id"].(string)] = it
	}
	// Imported users are invited, each with their own invitation.
	seen := map[string]bool{}
	for n, id := range []string{actImp1, actImp2} {
		it := items[id]
		inv, _ := it["invitation_id"].(string)
		if it["outcome"] != "invited" || it["reason"] != nil || !uuidRE.MatchString(inv) || seen[inv] {
			t.Fatalf("%s: %v", id, it)
		}
		seen[inv] = true
		stored, ok := a.ms.Invitations[inv]
		if !ok || stored.Email != fmt.Sprintf("imp%d@x.test", n+1) || stored.TenantID != tid {
			t.Fatalf("%s: invitation_id %s does not name its invitation (%+v)", id, inv, stored)
		}
		if got := a.status(t, tid, id); got != "invited" {
			t.Fatalf("%s: status %q", id, got)
		}
	}
	// Per-user failures do not affect the others and carry a closed reason.
	for id, reason := range map[string]string{actActive: "invalid_state", actUnknown: "not_found", actOther: "not_found"} {
		if it := items[id]; it["outcome"] != "failed" || it["reason"] != reason || it["invitation_id"] != nil {
			t.Fatalf("%s: want failed %s, got %v", id, reason, it)
		}
	}
	if got := a.status(t, tid, actActive); got != "active" {
		t.Fatalf("active user changed to %q", got)
	}
	if got := a.status(t, actTenant2, actOther); got != "imported" {
		t.Fatalf("other tenant's user changed to %q", got)
	}
	if len(a.ms.Invitations) != 2 || len(a.ms.Outbox) != 2 {
		t.Fatalf("want 2 invitations and 2 e-mails, got %d, %d", len(a.ms.Invitations), len(a.ms.Outbox))
	}
	// A second activation of an already invited user fails per user.
	w, out = a.call("POST", "/api/v1/admin/users/activate", activateBody([]string{actImp1}, ""), a.owner)
	if raw, _ := out["items"].([]any); w.Code != 200 || len(raw) != 1 || raw[0].(map[string]any)["reason"] != "invalid_state" {
		t.Fatalf("re-activate → %d %v", w.Code, out)
	}
	// Roles and groups travel with the invitation.
	w, out = a.call("POST", "/api/v1/admin/groups", `{"name":"Imported staff"}`, a.owner)
	gid, _ := out["id"].(string)
	if w.Code != 201 || gid == "" {
		t.Fatalf("create group → %d %v", w.Code, out)
	}
	a.ms.AddRole(store.Role{ID: "0190f7c2-6a3e-7c1a-9b2e-00000000e001", TenantID: tid, Slug: "viewer"})
	w, out = a.call("POST", "/api/v1/admin/users/activate",
		activateBody([]string{actImp3}, `,"role_ids":["0190f7c2-6a3e-7c1a-9b2e-00000000e001"],"group_ids":["`+gid+`"]`), a.owner)
	if w.Code != 200 {
		t.Fatalf("with roles/groups → %d %v", w.Code, out)
	}
	inv := a.invitationsFor("imp3@x.test")
	if len(inv) != 1 || len(inv[0].RoleIDs) != 1 || len(inv[0].GroupIDs) != 1 || inv[0].GroupIDs[0] != gid {
		t.Fatalf("invitation %+v", inv)
	}
}

func TestActivateSelfEscalation(t *testing.T) {
	a := newActHarness(t)
	// An admin (not owner) cannot hand out the owner role: the whole request is
	// refused before any invitation, e-mail or status change.
	w, out := a.call("POST", "/api/v1/admin/users/activate", activateBody([]string{actImp1, actImp2}, `,"role_ids":["r-owner"]`), a.admin)
	if w.Code != 403 || out["reason"] != "self_escalation" || len(out) != 1 {
		t.Fatalf("admin granting owner → %d %v", w.Code, out)
	}
	for _, id := range []string{actImp1, actImp2} {
		if got := a.status(t, tid, id); got != "imported" {
			t.Fatalf("%s: status %q after refusal", id, got)
		}
	}
	if len(a.ms.Invitations) != 0 || len(a.ms.Outbox) != 0 {
		t.Fatalf("refusal left %d invitations, %d outbox rows", len(a.ms.Invitations), len(a.ms.Outbox))
	}
	// The owner may.
	if w, out := a.call("POST", "/api/v1/admin/users/activate", activateBody([]string{actImp1}, `,"role_ids":["r-owner"]`), a.owner); w.Code != 200 {
		t.Fatalf("owner granting owner → %d %v", w.Code, out)
	}
}

func TestRemoveImported(t *testing.T) {
	a := newActHarness(t)
	path := func(id string) string { return "/api/v1/admin/users/" + id + "/remove-imported" }
	// Gate and CSRF first: nothing is removed.
	for name, c := range map[string]*http.Cookie{"member": a.member, "directory:manage only": a.importer} {
		if w, out := a.call("POST", path(actImp4), "", c); w.Code != 403 || out["reason"] != "forbidden" {
			t.Fatalf("%s → %d %v", name, w.Code, out)
		}
	}
	if w := a.callNoCSRF("POST", path(actImp4), "", a.owner); w.Code/100 != 4 {
		t.Fatalf("no CSRF → %d", w.Code)
	}
	if got := a.status(t, tid, actImp4); got != "imported" {
		t.Fatalf("refused removal changed the user: %q", got)
	}
	// An imported user is deleted: 204, empty body, no e-mail.
	w, _ := a.call("POST", path(actImp4), "", a.admin)
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("remove → %d %q", w.Code, w.Body.String())
	}
	if got := a.status(t, tid, actImp4); got != "<deleted>" {
		t.Fatalf("user still present: %q", got)
	}
	if len(a.ms.Outbox) != 0 {
		t.Fatalf("removal queued %d e-mails", len(a.ms.Outbox))
	}
	// Anything not imported → 409 invalid_state and untouched.
	if w, out := a.call("POST", "/api/v1/admin/users/activate", activateBody([]string{actImp5}, ""), a.owner); w.Code != 200 {
		t.Fatalf("activate → %d %v", w.Code, out)
	}
	for id, was := range map[string]string{actActive: "active", actImp5: "invited", "u2": "active"} {
		if w, out := a.call("POST", path(id), "", a.owner); w.Code != 409 || out["reason"] != "invalid_state" {
			t.Fatalf("%s (%s) → %d %v", id, was, w.Code, out)
		}
		if got := a.status(t, tid, id); got != was {
			t.Fatalf("%s: status %q, want %q", id, got, was)
		}
	}
	// Unknown, already removed and other-tenant ids → 404 not_found.
	for _, id := range []string{actUnknown, actImp4, actOther} {
		if w, out := a.call("POST", path(id), "", a.owner); w.Code != 404 || out["reason"] != "not_found" {
			t.Fatalf("%s → %d %v", id, w.Code, out)
		}
	}
	if got := a.status(t, actTenant2, actOther); got != "imported" {
		t.Fatalf("other tenant's user: %q", got)
	}
}

// A plain invitation to an imported address converts it (research D10) and is
// indistinguishable on the wire from any other invitation.
func TestInvitationToImportedEmailIsIdentical(t *testing.T) {
	a := newActHarness(t)
	bodies := map[string]string{}
	for name, addr := range map[string]string{"new": "fresh@x.test", "active": "act@x.test", "imported": "IMP1@x.test"} {
		w, out := a.call("POST", "/api/v1/admin/invitations", `{"email":"`+addr+`"}`, a.owner)
		if w.Code != 202 || out["queued"] != true || len(out) != 1 {
			t.Fatalf("%s → %d %v", name, w.Code, out)
		}
		bodies[name] = w.Body.String()
	}
	if bodies["imported"] != bodies["new"] || bodies["imported"] != bodies["active"] {
		t.Fatalf("bodies differ: %q", bodies)
	}
	// The imported row became the invited account: no second user row.
	if got := a.status(t, tid, actImp1); got != "invited" {
		t.Fatalf("imported address: status %q", got)
	}
	n := 0
	for _, u := range a.ms.Users {
		if u.TenantID == tid && strings.EqualFold(u.Email, "imp1@x.test") {
			n++
		}
	}
	if n != 1 || len(a.invitationsFor("imp1@x.test")) != 1 {
		t.Fatalf("users=%d invitations=%d for the imported address", n, len(a.invitationsFor("imp1@x.test")))
	}
	// Escalation now applies to plain invitations too.
	if w, out := a.call("POST", "/api/v1/admin/invitations", `{"email":"imp2@x.test","role_ids":["r-owner"]}`, a.admin); w.Code != 403 || out["reason"] != "self_escalation" {
		t.Fatalf("admin inviting an owner → %d %v", w.Code, out)
	}
	if got := a.status(t, tid, actImp2); got != "imported" || len(a.invitationsFor("imp2@x.test")) != 0 {
		t.Fatalf("refused invitation changed state: %q", got)
	}
}
