package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the TimescaleDB persistence layer. Every tenant-scoped query runs
// inside a transaction that sets app.tenant_id (RLS, SR-001).
type Store struct{ pool *pgxpool.Pool }

// Open connects with the application DSN.
func Open(ctx context.Context, dsn string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies the embedded migrations with the migration DSN, guarded by a
// PostgreSQL advisory lock so several instances can start concurrently.
func Migrate(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock(7241001)"); err != nil {
		return fmt.Errorf("store: migrate lock: %w", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, "SELECT pg_advisory_unlock(7241001)") }()
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// MigrateTo applies migrations up to and including version (tests: upgrade paths).
func MigrateTo(ctx context.Context, dsn string, version int64) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.UpToContext(ctx, db, "migrations", version); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Scope selects which RLS settings a transaction runs under.
type Scope struct {
	TenantID      string // app.tenant_id
	OperatorGrant string // app.operator_grant (tenant the grant targets)
	Operator      bool   // app.operator: may list tenants
	System        bool   // app.system: keys, bootstrap, cross-tenant workers
}

// Tx runs fn in a transaction with the scope's settings applied via set_config(local).
func (s *Store) Tx(ctx context.Context, scope Scope, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := applyScope(ctx, tx, scope); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func applyScope(ctx context.Context, tx pgx.Tx, sc Scope) error {
	set := func(k, v string) error {
		_, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", k, v)
		return err
	}
	if sc.TenantID != "" {
		if err := set("app.tenant_id", sc.TenantID); err != nil {
			return err
		}
	}
	if sc.OperatorGrant != "" {
		if err := set("app.operator_grant", sc.OperatorGrant); err != nil {
			return err
		}
	}
	if sc.Operator {
		if err := set("app.operator", "on"); err != nil {
			return err
		}
	}
	if sc.System {
		if err := set("app.system", "on"); err != nil {
			return err
		}
	}
	return nil
}

// ErrNotFound is returned for missing or foreign-tenant rows alike.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a unique constraint refuses an insert.
var ErrConflict = errors.New("store: conflict")

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// Now is the clock used for timestamps (overridable in tests).
var Now = time.Now

// InsertAuditRows writes an audit batch under the system scope (audit.Inserter).
func (s *Store) InsertAuditRows(ctx context.Context, rows []AuditRow) error {
	return s.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error { return InsertAuditRows(ctx, tx, rows) })
}
