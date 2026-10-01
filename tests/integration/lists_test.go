//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Server-side tables (go-tangra specs/032-server-side-tables, T124) against
// the real database: every user reachable with an exact total, audit pages
// that never skip events sharing a timestamp, the default audit window, and
// every console list paged and sorted under its permission check.

type listPage struct {
	Items      []map[string]any `json:"items"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	Sort       string           `json:"sort"`
	Order      string           `json:"order"`
	NextCursor string           `json:"next_cursor"`
}

// rawGet returns the status and body of a GET (see get in profile_test.go).
func (e *Env) rawGet(path string) (int, []byte) {
	e.T.Helper()
	code, _, b := e.get(path)
	return code, b
}

func (e *Env) listPage(path string) listPage {
	e.T.Helper()
	code, b := e.rawGet(path)
	if code != 200 {
		e.T.Fatalf("GET %s → %d %s", path, code, b)
	}
	var p listPage
	if err := json.Unmarshal(b, &p); err != nil {
		e.T.Fatalf("GET %s: %v %s", path, err, b)
	}
	return p
}

// collect pages through path (which has no page parameter) and returns every
// item id, failing on a repeat.
func (e *Env) collect(path, idKey string, size int) (map[string]bool, int) {
	e.T.Helper()
	seen, total := map[string]bool{}, 0
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for p := 1; p < 1000; p++ {
		pg := e.listPage(fmt.Sprintf("%s%spage=%d&page_size=%d", path, sep, p, size))
		total = pg.Total
		for _, it := range pg.Items {
			id := fmt.Sprint(it[idKey])
			if seen[id] {
				e.T.Fatalf("%s: %s repeated on page %d", path, id, p)
			}
			seen[id] = true
		}
		if p*size >= pg.Total {
			break
		}
	}
	return seen, total
}

func TestServerSideLists(t *testing.T) {
	e := Start(t)
	ctx := context.Background()
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	otherTID, _ := e.Seed("globex", "someone@globex.test", pw, "")

	// 230 more users: well beyond the old 200-row cap.
	const extra = 230
	if err := e.App.Store.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		for i := 0; i < extra; i++ {
			if err := store.InsertUser(ctx, tx, store.User{ID: store.NewID(), TenantID: tid, Email: fmt.Sprintf("user%03d@acme.test", i), DisplayName: fmt.Sprintf("User %03d", i), Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code := e.SignIn("acme", "owner@acme.test", pw); code != 200 {
		t.Fatal(code)
	}

	t.Run("users", func(t *testing.T) {
		seen, total := e.collect("/api/v1/admin/users", "id", 200)
		if total != extra+1 || len(seen) != extra+1 {
			t.Fatalf("total %d, reached %d (want %d)", total, len(seen), extra+1)
		}
		for _, s := range []string{"email", "display_name", "status", "last_signin_at", "created_at"} {
			for _, o := range []string{"asc", "desc"} {
				if seen, total := e.collect("/api/v1/admin/users?sort="+s+"&order="+o, "id", 97); total != extra+1 || len(seen) != extra+1 {
					t.Fatalf("sort %s %s: total %d reached %d", s, o, total, len(seen))
				}
			}
		}
		pg := e.listPage("/api/v1/admin/users?sort=email&order=desc&page_size=1")
		if pg.Items[0]["email"] != "user229@acme.test" {
			t.Fatalf("desc first %v", pg.Items[0])
		}
		if pg := e.listPage("/api/v1/admin/users?q=user01"); pg.Total != 10 {
			t.Fatalf("filtered total %d", pg.Total)
		}
		if pg := e.listPage("/api/v1/admin/users?page=999&page_size=100"); pg.Page != 3 || len(pg.Items) != extra+1-200 {
			t.Fatalf("beyond last page: page %d items %d", pg.Page, len(pg.Items))
		}
		id := pg.Items[0]["id"].(string)
		if code, out := e.JSON(http.MethodGet, "/api/v1/admin/users/"+id, nil); code != 200 || out["email"] != "user229@acme.test" {
			t.Fatalf("get user → %d %v", code, out)
		}
		code, body := e.rawGet("/api/v1/admin/users?sort=password_hash")
		if code != 400 || !strings.Contains(string(body), `"param":"sort"`) || strings.Contains(string(body), "password_hash") {
			t.Fatalf("bad sort → %d %s", code, body)
		}
	})

	t.Run("audit", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		var rows []store.AuditRow
		for i := 0; i < 7; i++ { // seven events in the same microsecond
			r, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: tid, ActorKind: "user", Outcome: "ok", Reason: fmt.Sprintf("r%d", i)}, now.Add(-time.Hour))
			rows = append(rows, r)
		}
		old, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: tid, ActorKind: "user", Outcome: "ok", Reason: "old"}, now.Add(-10*24*time.Hour))
		other, _ := audit.Row(audit.Event{Type: audit.TenantSuspended, TenantID: otherTID, ActorKind: "user", Outcome: "ok"}, now.Add(-time.Hour))
		// Inserted as the application role: the id sequence is granted to it.
		if err := e.App.Store.InsertAuditRows(ctx, append(rows, old, other)); err != nil {
			t.Fatal(err)
		}
		seen, total := e.collect("/api/v1/admin/audit?event_type=tenant_suspended", "id", 2)
		if total != 7 || len(seen) != 7 {
			t.Fatalf("default window: total %d reached %d", total, len(seen))
		}
		from := url.QueryEscape(now.Add(-30 * 24 * time.Hour).Format(time.RFC3339))
		if seen, total := e.collect("/api/v1/admin/audit?event_type=tenant_suspended&from="+from, "id", 3); total != 8 || len(seen) != 8 {
			t.Fatalf("explicit window: total %d reached %d", total, len(seen))
		}
		// Legacy cursor: old shape plus total; the id in the cursor keeps
		// equal timestamps from being skipped.
		legacy, cursor := map[string]bool{}, ""
		for i := 0; i < 10; i++ {
			path := "/api/v1/admin/audit?event_type=tenant_suspended&limit=3"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			pg := e.listPage(path)
			if pg.Total != 7 || pg.Page != 0 { // default window: the 10-day-old event is out
				t.Fatalf("legacy page %+v", pg)
			}
			for _, it := range pg.Items {
				legacy[it["id"].(string)] = true
			}
			if cursor = pg.NextCursor; cursor == "" {
				break
			}
		}
		if len(legacy) != 7 {
			t.Fatalf("legacy reached %d of 7", len(legacy))
		}
		if code, body := e.rawGet("/api/v1/admin/audit?cursor=1&page=2"); code != 400 || !strings.Contains(string(body), `"param":"cursor"`) {
			t.Fatalf("mixed styles → %d %s", code, body)
		}
	})

	t.Run("groups and members", func(t *testing.T) {
		var gid string
		for _, name := range []string{"Zeta", "alpha", "Mid"} {
			code, out := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]string{"name": name})
			if code != 201 {
				t.Fatalf("create group %d %v", code, out)
			}
			if name == "Zeta" {
				gid = out["id"].(string)
			}
		}
		pg := e.listPage("/api/v1/admin/groups?page_size=2")
		if pg.Total != 3 || len(pg.Items) != 2 || pg.Items[0]["name"] != "alpha" || pg.Items[1]["name"] != "Mid" {
			t.Fatalf("groups %+v", pg)
		}
		users := e.listPage("/api/v1/admin/users?page_size=5&sort=email")
		var ids []string
		for _, it := range users.Items {
			ids = append(ids, it["id"].(string))
		}
		if code, out := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+gid+"/members", map[string]any{"user_ids": ids}); code != 200 {
			t.Fatalf("add members %d %v", code, out)
		}
		seen, total := e.collect("/api/v1/admin/groups/"+gid+"/members", "user_id", 2)
		if total != 5 || len(seen) != 5 {
			t.Fatalf("members total %d reached %d", total, len(seen))
		}
		if pg := e.listPage("/api/v1/admin/groups/" + gid + "/members?sort=email&page_size=1"); pg.Items[0]["email"] != users.Items[0]["email"] {
			t.Fatalf("members by email %v", pg.Items)
		}
	})

	t.Run("roles, clients, sessions", func(t *testing.T) {
		code, body := e.rawGet("/api/v1/admin/roles")
		var all []map[string]any
		if code != 200 || json.Unmarshal(body, &all) != nil {
			t.Fatalf("legacy roles must stay a bare array: %d %s", code, body)
		}
		if seen, total := e.collect("/api/v1/admin/roles?sort=slug", "id", 2); total != len(all) || len(seen) != len(all) {
			t.Fatalf("roles total %d reached %d of %d", total, len(seen), len(all))
		}
		for _, name := range []string{"Beta", "alpha"} {
			if code, out := e.JSON(http.MethodPost, "/api/v1/admin/clients", map[string]any{"display_name": name, "redirect_uris": []string{"https://app.example.org/cb"}, "public": true}); code != 201 {
				t.Fatalf("client %d %v", code, out)
			}
		}
		if pg := e.listPage("/api/v1/admin/clients?page_size=1"); pg.Total != 2 || pg.Items[0]["display_name"] != "alpha" {
			t.Fatalf("clients %+v", pg)
		}
		if pg := e.listPage("/api/v1/sessions?page_size=10"); pg.Total < 1 || pg.Sort != "created_at" {
			t.Fatalf("sessions %+v", pg)
		}
		// Directories are a permission-gated feature; when served, they page.
		if code, body := e.rawGet("/api/v1/admin/directories?page_size=5"); code == 200 && !strings.Contains(string(body), `"total"`) {
			t.Fatalf("directories %s", body)
		}
	})

	t.Run("operator tenants", func(t *testing.T) {
		if _, err := e.App.Bootstrap(t.Context(), "ops@example.org"); err != nil {
			t.Fatal(err)
		}
		mail := e.LastMail("ops@example.org")
		tok := strings.TrimSpace(strings.Split(mail[strings.Index(mail, "token=")+6:], "\n")[0])
		op := e.Browser()
		if code, out := op.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "Ops", "password": "operator-password-1"}); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
		seen, total := op.collect("/api/v1/operator/tenants?sort=slug", "id", 1)
		if total != 3 || len(seen) != 3 { // acme, globex, platform
			t.Fatalf("tenants total %d reached %d", total, len(seen))
		}
		if code, out := op.JSON(http.MethodGet, "/api/v1/operator/tenants/"+tid, nil); code != 200 || out["slug"] != "acme" {
			t.Fatalf("get tenant → %d %v", code, out)
		}
		if code, _ := e.rawGet("/api/v1/operator/tenants"); code != 403 {
			t.Fatalf("tenant admin on operator list → %d", code)
		}
	})
}
