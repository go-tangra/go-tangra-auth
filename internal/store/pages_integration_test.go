//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// listUsers is the first page of PageUsers (the tests' former ListUsers).
func listUsers(ctx context.Context, tx pgx.Tx, tenantID, q, status string, limit int) ([]User, error) {
	out, _, _, err := PageUsers(ctx, tx, tenantID, UserPageFilter{Q: q, Status: status}, listquery.Request{PageSize: limit})
	return out, err
}

// TestMigration0012AuditIDs: the audit id is numbered for existing rows,
// drawn from the sequence for new rows by the application role, and pages
// (list contract and legacy cursor) never skip events sharing a timestamp.
func TestMigration0012AuditIDs(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := MigrateTo(ctx, adminDSN, 11); err != nil {
		t.Fatal(err)
	}
	tA, tB := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	ts := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	for i := 0; i < 3; i++ { // pre-migration rows, same instant
		if _, err := admin.Exec(ctx, "INSERT INTO auth_audit_events (ts, tenant_id, event_type, actor_kind, outcome) VALUES ($1, $2, 'tenant_suspended', 'user', 'ok')", ts, tA); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	var nulls int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM auth_audit_events WHERE id IS NULL").Scan(&nulls); err != nil || nulls != 0 {
		t.Fatalf("existing rows numbered: %d nulls, %v", nulls, err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var rows []AuditRow
	for i := 0; i < 4; i++ {
		rows = append(rows, AuditRow{TS: ts, TenantID: tA, EventType: "tenant_suspended", ActorKind: "user", Outcome: "ok", Details: []byte("{}")})
	}
	rows = append(rows, AuditRow{TS: ts, TenantID: tB, EventType: "tenant_suspended", ActorKind: "user", Outcome: "ok", Details: []byte("{}")})
	if err := st.InsertAuditRows(ctx, rows); err != nil {
		t.Fatalf("application role inserts with the id sequence: %v", err)
	}
	in := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := st.Tx(ctx, Scope{TenantID: tA}, fn); err != nil {
			t.Fatal(err)
		}
	}
	f := AuditPageFilter{From: ts.Add(-time.Hour), To: ts.Add(time.Hour)}
	seen := map[int64]bool{}
	for p := 1; p <= 4; p++ {
		in(func(tx pgx.Tx) error {
			page, total, applied, err := PageAudit(ctx, tx, tA, f, listquery.Request{Page: p, PageSize: 2})
			if err != nil {
				return err
			}
			if total != 7 || applied.Page != min(p, 4) {
				t.Fatalf("page %d: total %d applied %+v", p, total, applied)
			}
			for _, r := range page {
				if r.TenantID != tA {
					t.Fatalf("foreign row %+v", r)
				}
				seen[r.ID] = true
			}
			return nil
		})
	}
	if len(seen) != 7 {
		t.Fatalf("list pages reached %d of 7", len(seen))
	}
	// Legacy cursor (ts, id): three pages of three, nothing skipped.
	legacy := map[int64]bool{}
	var cur time.Time
	var curID int64
	for i := 0; i < 5; i++ {
		var got []AuditRow
		in(func(tx pgx.Tx) (err error) {
			got, err = QueryAudit(ctx, tx, tA, "", "", f.From, f.To, cur, curID, 3)
			return err
		})
		for _, r := range got {
			legacy[r.ID] = true
		}
		if len(got) < 3 {
			break
		}
		cur, curID = got[len(got)-1].TS, got[len(got)-1].ID
	}
	if len(legacy) != 7 {
		t.Fatalf("legacy cursor reached %d of 7", len(legacy))
	}
}
