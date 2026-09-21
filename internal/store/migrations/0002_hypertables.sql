-- +goose Up
-- Hypertables carry row-level security (0003). TimescaleDB does not allow
-- compression (columnstore) on RLS-protected hypertables, so these tables
-- keep retention policies only.
CREATE TABLE auth_audit_events (
  ts             timestamptz NOT NULL,
  tenant_id      uuid NOT NULL,
  event_type     text NOT NULL,
  actor_user_id  uuid,
  actor_kind     text NOT NULL,
  actor_service  text,
  subject_kind   text,
  subject_id     uuid,
  outcome        text NOT NULL CHECK (outcome IN ('ok','refused','failed')),
  reason         text NOT NULL DEFAULT '',
  origin_ip_hash text NOT NULL DEFAULT '',
  user_agent     text NOT NULL DEFAULT '',
  correlation_id text NOT NULL DEFAULT '',
  trace_id       text NOT NULL DEFAULT '',
  details        jsonb NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('auth_audit_events', 'ts', chunk_time_interval => INTERVAL '7 days');
CREATE INDEX auth_audit_tenant_ts ON auth_audit_events (tenant_id, ts DESC);
CREATE INDEX auth_audit_subject ON auth_audit_events (tenant_id, subject_id, ts DESC);
CREATE INDEX auth_audit_type ON auth_audit_events (tenant_id, event_type, ts DESC);
SELECT add_retention_policy('auth_audit_events', INTERVAL '400 days');

CREATE TABLE signin_attempts (
  ts         timestamptz NOT NULL,
  tenant_id  uuid,
  user_id    uuid,
  email_hash text NOT NULL,
  ip_hash    text NOT NULL,
  outcome    text NOT NULL,
  reason     text NOT NULL DEFAULT ''
);
SELECT create_hypertable('signin_attempts', 'ts', chunk_time_interval => INTERVAL '1 day');
SELECT add_retention_policy('signin_attempts', INTERVAL '30 days');

CREATE TABLE revocations (
  ts         timestamptz NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('session','user','tenant')),
  subject_id uuid NOT NULL,
  tenant_id  uuid NOT NULL,
  reason     text NOT NULL
);
SELECT create_hypertable('revocations', 'ts', chunk_time_interval => INTERVAL '10 minutes');
SELECT add_retention_policy('revocations', INTERVAL '1 hour');
CREATE INDEX revocations_ts ON revocations (ts);

-- +goose Down
DROP TABLE IF EXISTS revocations, signin_attempts, auth_audit_events;
