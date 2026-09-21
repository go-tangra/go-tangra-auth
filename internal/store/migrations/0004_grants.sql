-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT USAGE ON SCHEMA public TO auth_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_app;
    REVOKE UPDATE, DELETE ON auth_audit_events, signin_attempts, revocations FROM auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
