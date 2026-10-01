-- +goose Up
-- Server-side tables (go-tangra specs/032-server-side-tables, research D6/D10):
-- the users list pages by email (case-insensitive) or creation time with the
-- id tie-breaker, and audit pages need a unique id so events that share a
-- timestamp are never skipped or repeated between pages.
CREATE INDEX IF NOT EXISTS users_tenant_email ON users (tenant_id, lower(email), id);
CREATE INDEX IF NOT EXISTS users_tenant_created ON users (tenant_id, created_at, id);

-- auth_audit_events is a hypertable with row-level security, so it carries no
-- compression (0002); adding a bigserial column rewrites every chunk once and
-- numbers the existing rows (bounded by the 400-day retention).
ALTER TABLE auth_audit_events ADD COLUMN IF NOT EXISTS id bigserial;
CREATE INDEX IF NOT EXISTS auth_audit_tenant_ts_id ON auth_audit_events (tenant_id, ts DESC, id DESC);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT USAGE ON SEQUENCE auth_audit_events_id_seq TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS auth_audit_tenant_ts_id;
ALTER TABLE auth_audit_events DROP COLUMN IF EXISTS id;
DROP INDEX IF EXISTS users_tenant_created;
DROP INDEX IF EXISTS users_tenant_email;
