//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startDB(t *testing.T) (adminDSN, appDSN string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
			Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "auth"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	adminDSN = "postgres://postgres:test@" + host + ":" + port.Port() + "/auth?sslmode=disable"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, "CREATE ROLE auth_app LOGIN PASSWORD 'app' NOBYPASSRLS")
	_ = conn.Close(ctx)
	appDSN = "postgres://auth_app:app@" + host + ":" + port.Port() + "/auth?sslmode=disable"
	return
}

func TestMigrateAndRLS(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, adminDSN); err != nil { // idempotent
		t.Fatal(err)
	}
	admin, _ := pgx.Connect(ctx, adminDSN)
	defer admin.Close(ctx)
	var n int
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name IN ('auth_audit_events','signin_attempts','revocations')").Scan(&n)
	if n != 3 {
		t.Fatalf("hypertables %d", n)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_policies WHERE policyname = 'tenant_isolation'").Scan(&n)
	if n < 15 {
		t.Fatalf("policies %d", n)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tA, tB := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA, uB := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "tenant-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
			if err := InsertUser(ctx, tx, User{ID: []string{uA, uB}[i], TenantID: id, Email: "u@x.test", Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Tenant A scope cannot see tenant B's user, even with a direct query.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("RLS leak: %d users visible", n)
		}
		if _, err := GetUserByEmail(ctx, tx, tB, "u@x.test"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign tenant row returned: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Inserts into a foreign tenant are refused by the policy's WITH CHECK.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		return InsertUser(ctx, tx, User{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", TenantID: tB, Email: "evil@x.test", Status: "active"})
	}); err == nil {
		t.Fatal("cross-tenant insert must be refused by RLS")
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention'").Scan(&n)
	if n < 3 {
		t.Fatalf("retention jobs %d", n)
	}
}
