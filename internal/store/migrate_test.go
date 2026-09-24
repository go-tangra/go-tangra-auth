//go:build integration

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	defer func() { _ = admin.Close(ctx) }()
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

// sqlState returns the PostgreSQL error code of err, or "" when err is not a
// server error.
func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// Migration 0008 (feature 016, LDAP import): the imported user status, the
// directory_connections and user_directory_links tables, their uniqueness,
// foreign-key actions, RLS and grants.
func TestMigration0008LDAPImport(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tables := []string{"directory_connections", "user_directory_links"}

	t.Run("status constraint", func(t *testing.T) {
		var def string
		if err := admin.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = 'users'::regclass AND conname = 'users_status_check'`).Scan(&def); err != nil {
			t.Fatalf("users_status_check: %v", err)
		}
		for _, v := range []string{"invited", "active", "deactivated", "imported"} {
			if !strings.Contains(def, "'"+v+"'") {
				t.Errorf("users_status_check %q lacks %q", def, v)
			}
		}
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_constraint
			WHERE conrelid = 'users'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%status%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("status CHECK constraints on users: %d, want exactly 1 (old one must be replaced)", n)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_indexes
			WHERE tablename = 'users' AND indexname = 'users_imported_idx'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatal("users_imported_idx missing")
		}
	})

	t.Run("rls enabled and forced", func(t *testing.T) {
		for _, tbl := range tables {
			var enabled, forced bool
			if err := admin.QueryRow(ctx, "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass", tbl).Scan(&enabled, &forced); err != nil {
				t.Fatalf("%s: %v", tbl, err)
			}
			if !enabled || !forced {
				t.Errorf("%s: rls enabled=%v forced=%v", tbl, enabled, forced)
			}
			var n int
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_policies WHERE tablename = $1 AND policyname = 'tenant_isolation'", tbl).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("%s: tenant_isolation policies %d", tbl, n)
			}
		}
	})

	t.Run("auth_app grants", func(t *testing.T) {
		for _, tbl := range tables {
			for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				var ok bool
				if err := admin.QueryRow(ctx, "SELECT has_table_privilege('auth_app', $1, $2)", tbl, priv).Scan(&ok); err != nil {
					t.Fatal(err)
				}
				if !ok {
					t.Errorf("auth_app lacks %s on %s", priv, tbl)
				}
			}
		}
	})

	tA, tB := NewID(), NewID()
	sys := Scope{System: true}
	if err := st.Tx(ctx, sys, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "ldap-tenant-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// exec runs one statement in its own transaction under scope, so a
	// constraint violation does not poison later statements.
	exec := func(scope Scope, sql string, args ...any) error {
		return st.Tx(ctx, scope, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	insertUser := func(tenant, email, status string) (string, error) {
		id := NewID()
		return id, st.Tx(ctx, Scope{TenantID: tenant}, func(tx pgx.Tx) error {
			return InsertUser(ctx, tx, User{ID: id, TenantID: tenant, Email: email, Status: status})
		})
	}
	insertConn := func(tenant, name string) (string, error) {
		id := NewID()
		return id, exec(Scope{TenantID: tenant}, `INSERT INTO directory_connections
			(id, tenant_id, name, kind, url, tls_mode, bind_dn, bind_password_enc, base_dn, attr_uid, attr_email, attr_display_name)
			VALUES ($1, $2, $3, 'openldap', 'ldaps://ldap.example.test', 'ldaps', 'cn=reader,dc=example,dc=test', '\x00'::bytea,
			        'ou=Engineering,dc=example,dc=test', 'entryUUID', 'mail', 'cn')`, id, tenant, name)
	}
	insertLink := func(tenant, userID string, connID any, uid string) error {
		return exec(Scope{TenantID: tenant}, `INSERT INTO user_directory_links
			(user_id, tenant_id, connection_id, connection_name, directory_uid, directory_dn, first_imported_at, last_imported_at)
			VALUES ($1, $2, $3, 'Corp LDAP', $4, 'uid=x,ou=Engineering,dc=example,dc=test', now(), now())`, userID, tenant, connID, uid)
	}

	t.Run("users status values", func(t *testing.T) {
		if _, err := insertUser(tA, "imported@x.test", "imported"); err != nil {
			t.Fatalf("imported status refused: %v", err)
		}
		for _, bad := range []string{"bogus", "Imported", "suspended", ""} {
			if _, err := insertUser(tA, bad+"-status@x.test", bad); sqlState(err) != "23514" {
				t.Errorf("status %q: got %v, want check_violation", bad, err)
			}
		}
	})

	connA, err := insertConn(tA, "Corp LDAP")
	if err != nil {
		t.Fatalf("insert connection: %v", err)
	}
	userA, err := insertUser(tA, "linked@x.test", "imported")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertLink(tA, userA, connA, "uid-1"); err != nil {
		t.Fatalf("insert link: %v", err)
	}

	t.Run("connection name unique per tenant case-insensitively", func(t *testing.T) {
		if _, err := insertConn(tA, "corp ldap"); sqlState(err) != "23505" {
			t.Fatalf("duplicate name (case variant): got %v, want unique_violation", err)
		}
		if _, err := insertConn(tB, "Corp LDAP"); err != nil {
			t.Fatalf("same name in another tenant refused: %v", err)
		}
	})

	t.Run("link unique per tenant connection uid", func(t *testing.T) {
		other, err := insertUser(tA, "other@x.test", "imported")
		if err != nil {
			t.Fatal(err)
		}
		if err := insertLink(tA, other, connA, "uid-1"); sqlState(err) != "23505" {
			t.Fatalf("duplicate (tenant, connection, uid): got %v, want unique_violation", err)
		}
		if err := insertLink(tA, other, connA, "uid-2"); err != nil {
			t.Fatalf("distinct uid refused: %v", err)
		}
		if err := insertLink(tA, userA, connA, "uid-3"); sqlState(err) != "23505" {
			t.Fatalf("second link for one user: got %v, want unique_violation (user_id PK)", err)
		}
	})

	t.Run("tenant isolation", func(t *testing.T) {
		if err := st.Tx(ctx, Scope{TenantID: tB}, func(tx pgx.Tx) error {
			for _, tbl := range tables {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+tbl+" WHERE tenant_id = $1", tA).Scan(&n); err != nil {
					return err
				}
				if n != 0 {
					t.Errorf("RLS leak: tenant B sees %d tenant A rows in %s", n, tbl)
				}
			}
			// Updates and deletes aimed at tenant A rows touch nothing.
			tag, err := tx.Exec(ctx, "DELETE FROM directory_connections WHERE id = $1", connA)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Errorf("tenant B deleted tenant A connection")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := insertConn(tB, "x"); err != nil {
			t.Fatal(err)
		}
		// Writes into a foreign tenant are refused by WITH CHECK.
		if err := exec(Scope{TenantID: tB}, `INSERT INTO directory_connections
			(id, tenant_id, name, kind, url, tls_mode, bind_dn, bind_password_enc, base_dn, attr_uid, attr_email, attr_display_name)
			VALUES ($1, $2, 'evil', 'openldap', 'ldaps://h', 'ldaps', 'cn=a', '\x00'::bytea, 'dc=a', 'uid', 'mail', 'cn')`, NewID(), tA); err == nil {
			t.Error("cross-tenant connection insert must be refused by RLS")
		}
		if err := exec(Scope{TenantID: tB}, `INSERT INTO user_directory_links
			(user_id, tenant_id, connection_id, connection_name, directory_uid, directory_dn, first_imported_at, last_imported_at)
			VALUES ($1, $2, NULL, 'evil', 'uid-evil', 'uid=evil', now(), now())`, userA, tA); err == nil {
			t.Error("cross-tenant link insert must be refused by RLS")
		}
		// Tenant A still sees its own rows.
		var n int
		if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM user_directory_links").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Errorf("tenant A links visible: %d, want 2", n)
		}
	})

	t.Run("connection delete sets link connection null", func(t *testing.T) {
		if err := exec(Scope{TenantID: tA}, "DELETE FROM directory_connections WHERE id = $1", connA); err != nil {
			t.Fatalf("delete connection: %v", err)
		}
		var connID *string
		var name, status string
		if err := admin.QueryRow(ctx, `SELECT l.connection_id::text, l.connection_name, u.status
			FROM user_directory_links l JOIN users u ON u.id = l.user_id WHERE l.user_id = $1`, userA).Scan(&connID, &name, &status); err != nil {
			t.Fatalf("link or user lost on connection delete: %v", err)
		}
		if connID != nil {
			t.Errorf("connection_id = %s, want NULL", *connID)
		}
		if name != "Corp LDAP" || status != "imported" {
			t.Errorf("link snapshot/user changed: name=%q status=%q", name, status)
		}
		// Orphaned links no longer collide on the same uid.
		other, err := insertUser(tA, "orphan@x.test", "imported")
		if err != nil {
			t.Fatal(err)
		}
		if err := insertLink(tA, other, nil, "uid-1"); err != nil {
			t.Fatalf("orphaned link with same uid refused: %v", err)
		}
	})

	t.Run("user delete cascades link", func(t *testing.T) {
		if err := exec(Scope{TenantID: tA}, "DELETE FROM users WHERE id = $1", userA); err != nil {
			t.Fatalf("delete user: %v", err)
		}
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM user_directory_links WHERE user_id = $1", userA).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("link survived user delete: %d", n)
		}
	})
}
