//go:build integration

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestOutboxRetire covers 0009 (feature 017): ClaimOutbox backs off
// exponentially (30 s · 2^n, capped at 1 h) and never claims a retired row;
// MarkOutboxFailed retires with a bounded reason. A row left by auth ≤ 4.1
// keeps working after the migration.
func TestOutboxRetire(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	admin, _ := pgx.Connect(ctx, adminDSN)
	defer func() { _ = admin.Close(ctx) }()
	if err := MigrateTo(ctx, adminDSN, 8); err != nil {
		t.Fatal(err)
	}
	tid := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	old := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c01"
	if _, err := admin.Exec(ctx, "INSERT INTO tenants (id, slug, display_name, status, kind, policy) VALUES ($1,'tenant-old','T','active','customer','{}')", tid); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO outbox (id, tenant_id, kind, to_email, payload_enc, attempts) VALUES ($1,$2,'invite','old@x.test','\\x00',3)", old, tid); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sys := Scope{System: true}
	claim := func() (out []OutboxItem) {
		t.Helper()
		if err := st.Tx(ctx, sys, func(tx pgx.Tx) error { out, err = ClaimOutbox(ctx, tx, 50); return err }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	due := func(id string) {
		t.Helper()
		if _, err := admin.Exec(ctx, "UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE id = $1", id); err != nil {
			t.Fatal(err)
		}
	}
	// The pre-migration row is claimed; attempts 3 → 4, next in 30 s · 2^3.
	items := claim()
	if len(items) != 1 || items[0].ID != old || items[0].Attempts != 4 {
		t.Fatalf("claim %+v", items)
	}
	if d := time.Until(items[0].NextAttemptAt); d < 230*time.Second || d > 250*time.Second {
		t.Fatalf("backoff after 3 attempts %v", d)
	}
	if len(claim()) != 0 {
		t.Fatal("a claimed row waits for its next attempt")
	}
	// A fresh row: first retry in 30 s.
	fresh := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c02"
	if err := st.Tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		return EnqueueOutbox(ctx, tx, OutboxItem{ID: fresh, TenantID: tid, Kind: "recovery", ToEmail: "new@x.test", PayloadEnc: []byte{1}})
	}); err != nil {
		t.Fatal(err)
	}
	items = claim()
	if len(items) != 1 || items[0].ID != fresh || items[0].Attempts != 1 {
		t.Fatalf("claim fresh %+v", items)
	}
	if d := time.Until(items[0].NextAttemptAt); d < 20*time.Second || d > 40*time.Second {
		t.Fatalf("first backoff %v", d)
	}
	// Many attempts: capped at one hour (no interval overflow).
	if _, err := admin.Exec(ctx, "UPDATE outbox SET attempts = 5000 WHERE id = $1", fresh); err != nil {
		t.Fatal(err)
	}
	due(fresh)
	items = claim()
	if len(items) != 1 {
		t.Fatalf("claim capped %+v", items)
	}
	if d := time.Until(items[0].NextAttemptAt); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("capped backoff %v", d)
	}
	// Retire both; the reason is clipped to 200 characters. Retired rows are
	// never claimed again, even when due.
	if err := st.Tx(ctx, sys, func(tx pgx.Tx) error {
		if err := MarkOutboxFailed(ctx, tx, old, strings.Repeat("é", 300)); err != nil {
			return err
		}
		return MarkOutboxFailed(ctx, tx, fresh, "550 no such user")
	}); err != nil {
		t.Fatal(err)
	}
	due(old)
	due(fresh)
	if n := len(claim()); n != 0 {
		t.Fatalf("retired rows claimed: %d", n)
	}
	var reason string
	var failed *time.Time
	if err := admin.QueryRow(ctx, "SELECT last_error, failed_at FROM outbox WHERE id = $1", old).Scan(&reason, &failed); err != nil {
		t.Fatal(err)
	}
	if len([]rune(reason)) != 200 || failed == nil {
		t.Fatalf("retired row: %d chars, failed_at %v", len([]rune(reason)), failed)
	}
	// The database refuses a longer reason whatever the caller does.
	if _, err := admin.Exec(ctx, "UPDATE outbox SET last_error = $2 WHERE id = $1", old, strings.Repeat("x", 201)); err == nil {
		t.Fatal("last_error longer than 200 accepted")
	}
	var idx string
	_ = admin.QueryRow(ctx, "SELECT indexdef FROM pg_indexes WHERE indexname = 'outbox_pending_idx'").Scan(&idx)
	if !strings.Contains(idx, "failed_at IS NULL") || !strings.Contains(idx, "sent_at IS NULL") {
		t.Fatalf("pending index %q", idx)
	}
}
