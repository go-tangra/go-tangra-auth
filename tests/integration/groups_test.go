//go:build integration

package integration

import (
	"context"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
)

// TestGroups: quickstart §2 — a group grants and withdraws access through the
// real OpenFGA model, the session sees the new effective roles without a new
// sign-in, sources are reported, and every change is audited once.
func TestGroups(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	if _, err := e.App.Registry.Register(svcCtx(), tid, "billing", "spiffe://example.org/svc/test", []authz.Permission{{Resource: "invoices", Action: "read"}, {Resource: "invoices", Action: "write"}}); err != nil {
		t.Fatal(err)
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, reader := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "invoices-reader", "display_name": "Invoices", "permissions": []string{"billing:invoices:read"}})
	readerID := reader["id"].(string)
	_, dana := e.Seed("acme", "dana@acme.test", pw, "")
	e.Bind(tid, dana, roles) // member only
	read := authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "read"}

	// Dana signs in before the group exists: her session must pick up the group's role later.
	db := e.Browser()
	if code := db.SignIn("acme", "dana@acme.test", pw); code != 200 {
		t.Fatalf("dana sign-in: %d", code)
	}
	if _, out := db.JSON(http.MethodGet, "/api/v1/session", nil); len(out["roles"].([]any)) != 0 {
		t.Fatalf("dana must start without roles: %v", out)
	}

	code, g := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "Finance", "description": "money"})
	if code != 201 {
		t.Fatalf("%d %v", code, g)
	}
	gid := g["id"].(string)
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/groups/"+gid+"/roles", map[string]any{"role_ids": []string{readerID}}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/members", map[string]any{"user_ids": []string{dana}}); code != 200 || out["added"].(float64) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	deadline := time.Now().Add(time.Second)
	for {
		d, err := e.App.Decider.Decide(svcCtx(), tid, dana, read)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed {
			if d.Reason != "role:invoices-reader" {
				t.Fatalf("reason must name the granting role: %+v", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("group membership not effective within 1 s: %+v", d)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// SC-002: the existing session reports the effective roles without re-login.
	if _, out := db.JSON(http.MethodGet, "/api/v1/session", nil); len(out["roles"].([]any)) != 1 || out["roles"].([]any)[0] != "invoices-reader" {
		t.Fatalf("session roles must refresh: %v", out)
	}
	a, err := e.App.Sessions.ByID(context.Background(), tid, sessionIDOf(t, db))
	if err != nil || len(a.Roles) != 1 {
		t.Fatalf("ByID (token minting) roles %v %v", a.Roles, err)
	}
	// Sources.
	_, eff := e.JSON(http.MethodGet, "/api/v1/admin/users/"+dana+"/effective-roles", nil)
	items := eff["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["sources"].([]any)[0].(map[string]any)["group_name"] != "Finance" {
		t.Fatalf("effective roles %v", eff)
	}
	// Direct + group: removing from the group keeps the direct role.
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+dana+"/roles", map[string]any{"role_ids": []string{readerID}}); code != 200 {
		t.Fatal(code)
	}
	_, eff = e.JSON(http.MethodGet, "/api/v1/admin/users/"+dana+"/effective-roles", nil)
	if len(eff["items"].([]any)[0].(map[string]any)["sources"].([]any)) != 2 {
		t.Fatalf("two sources expected: %v", eff)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/members/"+dana+"/remove", nil); code != 204 {
		t.Fatal(code)
	}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); !d.Allowed {
		t.Fatalf("direct grant must survive group removal: %+v", d)
	}
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+dana+"/roles", map[string]any{"role_ids": []string{}}); code != 200 {
		t.Fatal(code)
	}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); d.Allowed {
		t.Fatalf("no roles left: %+v", d)
	}
	// Back in the group; a deactivated member is denied; reactivation restores.
	e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/members", map[string]any{"user_ids": []string{dana}})
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); !d.Allowed {
		t.Fatalf("re-added: %+v", d)
	}
	e.JSON(http.MethodPost, "/api/v1/admin/users/"+dana+"/deactivate", nil)
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); d.Allowed || d.Reason != authz.ReasonUserInactive {
		t.Fatalf("deactivated member: %+v", d)
	}
	e.JSON(http.MethodPost, "/api/v1/admin/users/"+dana+"/reactivate", nil)
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); !d.Allowed {
		t.Fatalf("reactivated member keeps membership: %+v", d)
	}
	// Deleting the role withdraws it from the group; deleting the group withdraws everything.
	_, writer := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "invoices-writer", "display_name": "W", "permissions": []string{"billing:invoices:write"}})
	e.JSON(http.MethodPut, "/api/v1/admin/groups/"+gid+"/roles", map[string]any{"role_ids": []string{readerID, writer["id"].(string)}})
	write := authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "write"}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, write); !d.Allowed {
		t.Fatalf("second group role: %+v", d)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/roles/"+writer["id"].(string)+"/remove", nil); code != 204 {
		t.Fatalf("role delete %d", code)
	}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, write); d.Allowed {
		t.Fatalf("deleted role must stop granting through the group: %+v", d)
	}
	if code, out := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/remove", map[string]any{"member_count": 0}); code != 409 || out["reason"] != "member_count_mismatch" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/remove", map[string]any{"member_count": 1}); code != 204 {
		t.Fatal(code)
	}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, dana, read); d.Allowed {
		t.Fatalf("deleted group must withdraw access: %+v", d)
	}
	// SC-008: one audit event per change (group_deleted: one refused count mismatch + one ok).
	for ev, want := range map[string]int{"group_created": 1, "group_deleted": 2, "group_member_added": 2, "group_member_removed": 1, "group_role_granted": 2, "group_role_revoked": 0} {
		if n := e.AuditCount(tid, ev); n != want {
			t.Errorf("%s: %d events, want %d", ev, n, want)
		}
	}
	// Cross-tenant: another tenant's admin cannot see or touch the groups.
	tb, ownerB := e.Seed("globex", "owner@globex.test", pw, "")
	rolesB := e.SeedRoles(tb)
	e.Bind(tb, ownerB, rolesB, "owner")
	bb := e.Browser()
	bb.SignIn("globex", "owner@globex.test", pw)
	_, gA := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "Secret"})
	if code, out := bb.JSON(http.MethodGet, "/api/v1/admin/groups/"+gA["id"].(string), nil); code != 404 || out["reason"] != "not_found" {
		t.Fatalf("cross-tenant read %d %v", code, out)
	}
	if code, _ := bb.JSON(http.MethodPost, "/api/v1/admin/groups/"+gA["id"].(string)+"/members", map[string]any{"user_ids": []string{ownerB}}); code != 404 {
		t.Fatalf("cross-tenant add %d", code)
	}
	if code, out := bb.JSON(http.MethodGet, "/api/v1/admin/groups", nil); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("cross-tenant list %d %v", code, out)
	}
}

// sessionIDOf reads the browser's session id from /api/v1/session.
func sessionIDOf(t *testing.T, b *Env) string {
	t.Helper()
	_, out := b.JSON(http.MethodGet, "/api/v1/session", nil)
	id, _ := out["session_id"].(string)
	if id == "" {
		t.Fatalf("no session: %v", out)
	}
	return id
}

// TestGroupDecisionLatency (SC-003): decisions for a member of twenty groups
// stay within 10 % of a user with a direct role only (p95, warm cache off).
func TestGroupDecisionLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency comparison")
	}
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, _ = e.App.Registry.Register(svcCtx(), tid, "billing", "svc", []authz.Permission{{Resource: "invoices", Action: "read"}})
	e.SignIn("acme", "owner@acme.test", pw)
	_, role := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "reader", "display_name": "R", "permissions": []string{"billing:invoices:read"}})
	_, direct := e.Seed("acme", "direct@acme.test", pw, "")
	e.JSON(http.MethodPut, "/api/v1/admin/users/"+direct+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}})
	_, grouped := e.Seed("acme", "grouped@acme.test", pw, "")
	for i := 0; i < 20; i++ {
		_, g := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "G" + string(rune('a'+i))})
		if i == 19 {
			e.JSON(http.MethodPut, "/api/v1/admin/groups/"+g["id"].(string)+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}})
		}
		e.JSON(http.MethodPost, "/api/v1/admin/groups/"+g["id"].(string)+"/members", map[string]any{"user_ids": []string{grouped}})
	}
	read := authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "read"}
	measure := func(uid string) time.Duration {
		var lat []time.Duration
		for i := 0; i < 200; i++ {
			// Bump the version so every decision goes to OpenFGA (no decision cache hits).
			_, _ = e.App.Cache.BumpTenantVersion(context.Background(), tid)
			start := time.Now()
			d, err := e.App.Decider.Decide(svcCtx(), tid, uid, read)
			if err != nil || !d.Allowed {
				t.Fatalf("%+v %v", d, err)
			}
			lat = append(lat, time.Since(start))
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return lat[len(lat)*95/100]
	}
	measure(direct) // warm up connections
	pd, pg := measure(direct), measure(grouped)
	t.Logf("p95 direct=%s grouped(20)=%s", pd, pg)
	if float64(pg) > float64(pd)*1.10+float64(2*time.Millisecond) {
		t.Errorf("SC-003: grouped p95 %s exceeds direct %s by more than 10%% (+2 ms floor)", pg, pd)
	}
}
