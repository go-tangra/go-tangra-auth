-- +goose Up
-- The session revocation vocabulary in code (internal/session) grew past the
-- original check constraint; align the constraint with every reason the
-- service writes (old values stay valid for existing rows).
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_revoked_reason_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_revoked_reason_check CHECK (revoked_reason IS NULL OR revoked_reason IN (
  'signout', 'admin', 'password_change', 'deactivated', 'tenant_suspended', 'expired',
  'user_revoked', 'admin_revoked', 'password_changed', 'user_deactivated', 'idle_timeout'));

-- +goose Down
SELECT 1;
