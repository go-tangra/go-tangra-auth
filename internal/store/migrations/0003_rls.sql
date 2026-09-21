-- +goose Up
-- Row-level security: the application role (no BYPASSRLS) sets app.tenant_id
-- per transaction; operator grants set app.operator_grant to the target tenant.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app_tenant_matches(tid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT tid::text = current_setting('app.tenant_id', true)
      OR tid::text = current_setting('app.operator_grant', true)
      OR current_setting('app.system', true) = 'on'
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','recovery_codes','roles','role_bindings','permissions','role_permissions','sessions','invitations','recovery_requests','client_applications','operator_grants','outbox','auth_audit_events','signin_attempts','revocations']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id))', t);
  END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenants USING (app_tenant_matches(id) OR current_setting('app.operator', true) = 'on') WITH CHECK (current_setting('app.system', true) = 'on' OR current_setting('app.operator', true) = 'on');
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY keys_system ON signing_keys USING (current_setting('app.system', true) = 'on') WITH CHECK (current_setting('app.system', true) = 'on');

-- +goose Down
SELECT 1;
