package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// List contract (go-tangra specs/032-server-side-tables): pages, totals,
// sorting, validation errors naming the parameter only, and the legacy
// shapes kept for one release.

type pageBody struct {
	Items      []map[string]any `json:"items"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	Sort       string           `json:"sort"`
	Order      string           `json:"order"`
	NextCursor string           `json:"next_cursor"`
	Next       string           `json:"next"`
}

func (u *us1) page(t *testing.T, path string, c *http.Cookie) pageBody {
	t.Helper()
	w, _ := u.call("GET", path, "", c)
	if w.Code != 200 {
		t.Fatalf("GET %s → %d %s", path, w.Code, w.Body.String())
	}
	var p pageBody
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("GET %s: %v %s", path, err, w.Body.String())
	}
	return p
}

// refused asserts a 400 validation_failed naming param and not echoing the
// submitted value.
func (u *us1) refused(t *testing.T, path, param, value string, c *http.Cookie) {
	t.Helper()
	w, out := u.call("GET", path, "", c)
	detail, _ := out["detail"].(map[string]any)
	if w.Code != 400 || out["reason"] != "validation_failed" || detail == nil || detail["param"] != param {
		t.Fatalf("GET %s → %d %s (want param %q)", path, w.Code, w.Body.String(), param)
	}
	if value != "" && strings.Contains(w.Body.String(), value) {
		t.Fatalf("GET %s echoed the submitted value: %s", path, w.Body.String())
	}
}

func signinOwner(t *testing.T, u *us1) *http.Cookie {
	t.Helper()
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	c := sessionCookie(ow)
	if c == nil {
		t.Fatal("owner sign-in failed")
	}
	return c
}

func TestUsersListEveryUserReachable(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	const extra = 230
	for i := 0; i < extra; i++ {
		u.ms.AddUser(store.User{ID: fmt.Sprintf("0190f7c2-0000-7000-8000-%012d", i), TenantID: tid, Email: fmt.Sprintf("user%03d@x.test", i), Status: "active"})
	}
	// Another tenant's users are never counted.
	u.ms.AddUser(store.User{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Email: "eve@x.test", Status: "active"})
	owner := signinOwner(t, u)

	want := extra + 2 // alice, bob
	first := u.page(t, "/api/v1/admin/users", owner)
	if first.Total != want || len(first.Items) != 25 || first.Page != 1 || first.PageSize != 25 || first.Sort != "email" || first.Order != "asc" {
		t.Fatalf("defaults: total %d items %d page %d size %d %s %s", first.Total, len(first.Items), first.Page, first.PageSize, first.Sort, first.Order)
	}
	seen := map[string]bool{}
	for p := 1; ; p++ {
		pg := u.page(t, fmt.Sprintf("/api/v1/admin/users?page=%d&page_size=200", p), owner)
		if pg.Total != want {
			t.Fatalf("page %d total %d", p, pg.Total)
		}
		for _, it := range pg.Items {
			id := it["id"].(string)
			if seen[id] {
				t.Fatalf("user %s repeated", id)
			}
			seen[id] = true
		}
		if p*200 >= want {
			break
		}
	}
	if len(seen) != want {
		t.Fatalf("reached %d of %d users", len(seen), want)
	}
	// Sorting orders the whole list; a page beyond the end is the last page.
	desc := u.page(t, "/api/v1/admin/users?sort=email&order=desc&page_size=1", owner)
	if desc.Items[0]["email"] != "user229@x.test" || desc.Order != "desc" {
		t.Fatalf("desc %v", desc.Items)
	}
	last := u.page(t, "/api/v1/admin/users?page=999&page_size=100", owner)
	if last.Page != 3 || len(last.Items) != want-200 {
		t.Fatalf("beyond last: page %d items %d", last.Page, len(last.Items))
	}
	// Filters count what they match.
	if f := u.page(t, "/api/v1/admin/users?q=user01", owner); f.Total != 10 {
		t.Fatalf("filtered total %d", f.Total)
	}
	// One user by id (the detail view); another tenant's id is not found.
	if w, out := u.call("GET", "/api/v1/admin/users/u2", "", owner); w.Code != 200 || out["email"] != "bob@x.test" {
		t.Fatalf("get user → %d %v", w.Code, out)
	}
	if w, _ := u.call("GET", "/api/v1/admin/users/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", "", owner); w.Code != 404 {
		t.Fatalf("foreign user → %d", w.Code)
	}
}

func TestListValidationNamesTheParameter(t *testing.T) {
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	defer aw.Close()
	owner := signinOwner(t, u)
	for _, c := range []struct{ path, param, value string }{
		{"/api/v1/admin/users?sort=password_hash", "sort", "password_hash"},
		{"/api/v1/admin/users?order=sideways", "order", "sideways"},
		{"/api/v1/admin/users?page=0", "page", ""},
		{"/api/v1/admin/users?page=abc", "page", "abc"},
		{"/api/v1/admin/users?page_size=201", "page_size", ""},
		{"/api/v1/admin/users?page_size=0", "page_size", ""},
		{"/api/v1/admin/users?cursor=x&page=2", "cursor", ""},
		{"/api/v1/admin/audit?sort=details", "sort", "details"},
		{"/api/v1/admin/audit?cursor=1&page=1", "cursor", ""},
		{"/api/v1/admin/audit?limit=1000", "limit", ""},
		{"/api/v1/admin/audit?from=yesterday", "from", "yesterday"},
		// A window wider than 90 days (security review F-2), paged and legacy.
		{"/api/v1/admin/audit?from=1970-01-01T00:00:00Z", "from", "1970"},
		{"/api/v1/admin/audit?from=1970-01-01T00:00:00Z&page=1", "from", "1970"},
		{"/api/v1/admin/audit?from=1970-01-01T00:00:00Z&limit=5", "from", "1970"},
		{"/api/v1/admin/audit?from=2026-01-01T00:00:00Z&to=2026-04-02T00:00:00Z", "from", "2026"},
		{"/api/v1/admin/audit?from=2026-01-01T00:00:00Z&to=2026-04-02T00:00:00Z&cursor=", "from", "2026"},
		{"/api/v1/admin/groups?sort=secret", "sort", "secret"},
		{"/api/v1/admin/groups/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00/members?sort=phone", "sort", "phone"},
		{"/api/v1/admin/groups/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00/members?cursor=x&page_size=5", "cursor", ""},
		{"/api/v1/sessions?sort=secret_hash", "sort", "secret_hash"},
		{"/api/v1/sessions?page_size=-1", "page_size", ""},
	} {
		u.refused(t, c.path, c.param, c.value, owner)
	}
}

func TestAuditPagesNeverSkipEqualTimestamps(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	owner := signinOwner(t, u)
	aw.Flush()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	var rows []store.AuditRow
	for i := 0; i < 7; i++ { // seven events in the same instant
		r, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: tid, ActorKind: "user", Outcome: "ok", Reason: fmt.Sprintf("r%d", i)}, now.Add(-time.Hour))
		rows = append(rows, r)
	}
	old, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: tid, ActorKind: "user", Outcome: "ok", Reason: "old"}, now.Add(-10*24*time.Hour))
	other, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", ActorKind: "user", Outcome: "ok"}, now.Add(-time.Hour))
	_ = u.ms.InsertAuditRows(ctx, append(rows, old, other))

	// Default window: the last 7 days, newest first, id breaking ties.
	seen := map[string]bool{}
	for p := 1; p <= 4; p++ {
		pg := u.page(t, fmt.Sprintf("/api/v1/admin/audit?event_type=tenant_suspended&page_size=2&page=%d", p), owner)
		if pg.Total != 7 || pg.Sort != "ts" || pg.Order != "desc" {
			t.Fatalf("page %d: total %d %s %s", p, pg.Total, pg.Sort, pg.Order)
		}
		for _, it := range pg.Items {
			if seen[it["id"].(string)] {
				t.Fatalf("event %v repeated", it["id"])
			}
			seen[it["id"].(string)] = true
		}
	}
	if len(seen) != 7 {
		t.Fatalf("saw %d of 7 equal-timestamp events", len(seen))
	}
	from := url.QueryEscape(now.Add(-30 * 24 * time.Hour).Format(time.RFC3339))
	if pg := u.page(t, "/api/v1/admin/audit?event_type=tenant_suspended&from="+from, owner); pg.Total != 8 {
		t.Fatalf("explicit window total %d", pg.Total)
	}

	// Legacy cursor path: old shape plus total (default window too), and the
	// cursor carries the id so equal timestamps are not skipped either.
	legacy := map[string]bool{}
	cursor, total := "", -1
	for i := 0; i < 10; i++ {
		path := "/api/v1/admin/audit?event_type=tenant_suspended&limit=3"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		pg := u.page(t, path, owner)
		if pg.Page != 0 || pg.Sort != "" {
			t.Fatalf("legacy answered the page shape: %+v", pg)
		}
		total = pg.Total
		for _, it := range pg.Items {
			legacy[it["id"].(string)] = true
		}
		if cursor = pg.NextCursor; cursor == "" {
			break
		}
		if !strings.Contains(cursor, ".") {
			t.Fatalf("cursor without id: %q", cursor)
		}
	}
	if total != 7 || len(legacy) != 7 {
		t.Fatalf("legacy total %d, reached %d", total, len(legacy))
	}
	if pg := u.page(t, "/api/v1/admin/audit?event_type=tenant_suspended&limit=50&from="+from, owner); pg.Total != 8 || len(pg.Items) != 8 {
		t.Fatalf("legacy explicit window: total %d items %d", pg.Total, len(pg.Items))
	}
	// Exactly 90 days is accepted on both paths (the cap is 90 days).
	span := "&from=" + url.QueryEscape(now.Add(-90*24*time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Format(time.RFC3339))
	if pg := u.page(t, "/api/v1/admin/audit?event_type=tenant_suspended"+span, owner); pg.Total != 8 {
		t.Fatalf("90-day window total %d", pg.Total)
	}
	if pg := u.page(t, "/api/v1/admin/audit?event_type=tenant_suspended&limit=50"+span, owner); pg.Total != 8 {
		t.Fatalf("90-day legacy window total %d", pg.Total)
	}
	// A cursor of the previous release (ts only) is still accepted.
	prev := fmt.Sprint(now.UnixNano())
	if pg := u.page(t, "/api/v1/admin/audit?event_type=tenant_suspended&cursor="+prev, owner); len(pg.Items) != 7 {
		t.Fatalf("ts-only cursor: %d items", len(pg.Items))
	}
}

func TestSmallListsPageAndKeepLegacyArrays(t *testing.T) {
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	defer aw.Close()
	owner := signinOwner(t, u)

	// Own sessions: bare array without list parameters, a page with them.
	_ = signinOwner(t, u)
	w, _ := u.call("GET", "/api/v1/sessions", "", owner)
	var arr []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &arr); err != nil || w.Code != 200 || len(arr) != 2 {
		t.Fatalf("legacy sessions → %d %s", w.Code, w.Body.String())
	}
	if pg := u.page(t, "/api/v1/sessions?page_size=1", owner); pg.Total != 2 || len(pg.Items) != 1 || pg.Sort != "created_at" {
		t.Fatalf("sessions page %+v", pg)
	}

	// Groups and their members.
	var gids []string
	for _, name := range []string{"Zeta", "alpha", "Mid"} {
		_, out := u.call("POST", "/api/v1/admin/groups", `{"name":"`+name+`"}`, owner)
		gids = append(gids, out["id"].(string))
	}
	pg := u.page(t, "/api/v1/admin/groups?page_size=2", owner)
	if pg.Total != 3 || len(pg.Items) != 2 || pg.Items[0]["name"] != "alpha" || pg.Items[1]["name"] != "Mid" {
		t.Fatalf("groups page %+v", pg)
	}
	if pg := u.page(t, "/api/v1/admin/groups?q=a&sort=name&order=desc", owner); pg.Total != 2 || pg.Items[0]["name"] != "Zeta" {
		t.Fatalf("groups filtered %+v", pg)
	}
	for _, uid := range []string{"u1", "u2", "u3"} {
		if w, _ := u.call("POST", "/api/v1/admin/groups/"+gids[0]+"/members", `{"user_ids":["`+uid+`"]}`, owner); w.Code != 200 {
			t.Fatalf("add %s → %d", uid, w.Code)
		}
	}
	members := u.page(t, "/api/v1/admin/groups/"+gids[0]+"/members?page_size=2&sort=email", owner)
	if members.Total != 3 || len(members.Items) != 2 || members.Items[0]["email"] != "alice@x.test" {
		t.Fatalf("members page %+v", members)
	}
	legacy := u.page(t, "/api/v1/admin/groups/"+gids[0]+"/members?cursor=", owner)
	if legacy.Total != 3 || len(legacy.Items) != 3 || legacy.Page != 0 {
		t.Fatalf("legacy members %+v", legacy)
	}
	if w, _ := u.call("GET", "/api/v1/admin/groups/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00/members", "", owner); w.Code != 404 {
		t.Fatalf("unknown group members → %d", w.Code)
	}
	// A member without the admin role is refused before anything is counted.
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	if w, _ := u.call("GET", "/api/v1/admin/groups/"+gids[0]+"/members?page=1", "", sessionCookie(bw)); w.Code != 403 {
		t.Fatalf("member list as non-admin → %d", w.Code)
	}
}
