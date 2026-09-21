-- +goose Up
-- Single-use ledger for lcm enrollment (join) tokens: a JTI recorded here has
-- been consumed and must never be accepted again (replay/reuse protection).
-- Rows are prunable by expires_at. No RLS: this is a system-level ledger.
CREATE TABLE enrollment_jti (
  jti         uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_jti_expires ON enrollment_jti (expires_at);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, DELETE ON enrollment_jti TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS enrollment_jti;
