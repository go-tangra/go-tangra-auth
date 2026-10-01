//go:build integration

package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// explainTx runs EXPLAIN on every page query (Query; the count goes through
// QueryRow) before running it, so the plan checked is that of the exact SQL
// the page functions build.
type explainTx struct {
	pgx.Tx
	plans []string
}

func (e *explainTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := e.Tx.Query(ctx, "EXPLAIN (COSTS OFF) "+sql, args...)
	if err != nil {
		return nil, err
	}
	var lines []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			rows.Close()
			return nil, err
		}
		lines = append(lines, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	e.plans = append(e.plans, strings.Join(lines, "\n"))
	return e.Tx.Query(ctx, sql, args...)
}

// sortNode matches a Sort node and captures its sort key.
var sortNode = regexp.MustCompile(`(?m)^\s*(?:->\s+)?(?:Incremental )?Sort\s*\n\s*Sort Key: (.*)$`)

// pageSorts reports the Sort nodes of plan other than those whose key starts
// with one of the ignored prefixes.
func pageSorts(plan string, ignore []string) []string {
	var out []string
next:
	for _, m := range sortNode.FindAllStringSubmatch(plan, -1) {
		for _, p := range ignore {
			if strings.HasPrefix(m[1], p) {
				continue next
			}
		}
		out = append(out, m[1])
	}
	return out
}

// TestListSortsUseIndexes checks (032 perf) that the SQL list sorts are
// delivered in order by an index scan, without a Sort node, in both
// directions: users by email (0012) and created_at (0012), audit by ts
// (0012) and group members by added_at (0013). Seq and bitmap scans are
// disabled so the small test tables do not hide a missing or mis-ordered
// index.
func TestListSortsUseIndexes(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tA := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	gid := NewID()
	now := time.Now().UTC()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		if err := InsertTenant(ctx, tx, Tenant{ID: tA, Slug: "tenant-a", DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
			return err
		}
		var ids []string
		for i := 0; i < 20; i++ {
			u := User{ID: NewID(), TenantID: tA, Email: fmt.Sprintf("u%02d@x.test", i), Status: "active"}
			if err := InsertUser(ctx, tx, u); err != nil {
				return err
			}
			ids = append(ids, u.ID)
		}
		if err := InsertGroup(ctx, tx, Group{ID: gid, TenantID: tA, Name: "Finance"}); err != nil {
			return err
		}
		_, err := AddGroupMembers(ctx, tx, tA, gid, "", ids)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var events []AuditRow
	for i := 0; i < 20; i++ {
		events = append(events, AuditRow{TS: now.Add(-time.Duration(i) * time.Minute), TenantID: tA, EventType: "tenant_suspended", ActorKind: "user", Outcome: "ok", Details: []byte("{}")})
	}
	if err := st.InsertAuditRows(ctx, events); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		sorts []string
		// ignore lists sort keys of per-row subqueries (the users page's
		// newest pending invitation: a top-1 over the invited user's pending
		// invitations, not the page order).
		ignore []string
		run    func(tx pgx.Tx, req listquery.Request) error
	}{
		{name: "users", sorts: []string{"email", "created_at"}, ignore: []string{"i."}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageUsers(ctx, tx, tA, UserPageFilter{}, req)
			return err
		}},
		{name: "audit", sorts: []string{"ts"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageAudit(ctx, tx, tA, AuditPageFilter{From: now.Add(-time.Hour), To: now.Add(time.Minute)}, req)
			return err
		}},
		{name: "group members", sorts: []string{"added_at"}, run: func(tx pgx.Tx, req listquery.Request) error {
			_, _, _, err := PageGroupMembers(ctx, tx, tA, gid, req)
			return err
		}},
	}
	for _, c := range cases {
		for _, sort := range c.sorts {
			for _, dir := range []listquery.Dir{listquery.Desc, listquery.Asc} {
				e := &explainTx{}
				err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
					for _, set := range []string{"SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"} {
						if _, err := tx.Exec(ctx, set); err != nil {
							return err
						}
					}
					e.Tx = tx
					return c.run(e, listquery.Request{Page: 1, PageSize: 5, Sort: sort, Order: dir})
				})
				if err != nil {
					t.Fatalf("%s %s %s: %v", c.name, sort, dir, err)
				}
				if len(e.plans) != 1 {
					t.Fatalf("%s %s %s: %d page queries", c.name, sort, dir, len(e.plans))
				}
				if sorts := pageSorts(e.plans[0], c.ignore); len(sorts) > 0 {
					t.Errorf("%s by %s %s sorts instead of scanning an index:\n%s", c.name, sort, dir, e.plans[0])
				}
			}
		}
	}
}
