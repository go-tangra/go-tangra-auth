-- +goose Up
-- Feature 016: filtered LDAP import. Tenant directory connections (sealed bind
-- password), the per-user directory origin link, and the inactive "imported"
-- user status. Search/import runs are audit events only (no table).

CREATE TABLE directory_connections (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenants(id),
  name               text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  kind               text NOT NULL CHECK (kind IN ('active_directory','openldap','other')),
  url                text NOT NULL CHECK (char_length(url) <= 512 AND url ~ '^ldaps?://[^/?#@[:space:]]+$'),
  tls_mode           text NOT NULL CHECK (tls_mode IN ('ldaps','starttls','plain')),
  allow_tls12        boolean NOT NULL DEFAULT false,
  ca_pem             text CHECK (octet_length(ca_pem) <= 65536),
  bind_dn            text NOT NULL CHECK (char_length(bind_dn) BETWEEN 1 AND 1024),
  bind_password_enc  bytea NOT NULL,
  base_dn            text NOT NULL CHECK (char_length(base_dn) BETWEEN 1 AND 1024),
  base_filter        text NOT NULL DEFAULT '' CHECK (char_length(base_filter) <= 4096),
  attr_uid           text NOT NULL CHECK (attr_uid ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  attr_email         text NOT NULL CHECK (attr_email ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  attr_display_name  text NOT NULL CHECK (attr_display_name ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  attr_first_name    text NOT NULL DEFAULT '' CHECK (attr_first_name = '' OR attr_first_name ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  attr_last_name     text NOT NULL DEFAULT '' CHECK (attr_last_name = '' OR attr_last_name ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  size_limit         integer NOT NULL DEFAULT 500 CHECK (size_limit BETWEEN 1 AND 1000),
  time_limit_seconds integer NOT NULL DEFAULT 15 CHECK (time_limit_seconds BETWEEN 1 AND 60),
  last_test_at       timestamptz,
  last_test_outcome  text CHECK (last_test_outcome IN ('ok','unreachable','target_refused','timeout','tls_failed','invalid_credentials','base_not_found','directory_error')),
  created_by         uuid,
  updated_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX directory_connections_tenant_name ON directory_connections (tenant_id, lower(name));

CREATE TABLE user_directory_links (
  user_id           uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  tenant_id         uuid NOT NULL,
  connection_id     uuid REFERENCES directory_connections(id) ON DELETE SET NULL,
  connection_name   text NOT NULL,
  directory_uid     text NOT NULL CHECK (octet_length(directory_uid) BETWEEN 1 AND 256),
  directory_dn      text NOT NULL CHECK (char_length(directory_dn) <= 1024),
  first_imported_at timestamptz NOT NULL,
  last_imported_at  timestamptz NOT NULL,
  imported_by       uuid
);
-- The idempotency key; its (tenant_id, connection_id) prefix also serves the
-- per-connection lookups. NULL connection_id (deleted source) never collides.
CREATE UNIQUE INDEX user_directory_links_source_uid ON user_directory_links (tenant_id, connection_id, directory_uid);

-- Inline CHECK from 0001 gets the generated name users_status_check.
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('invited','active','deactivated','imported'));
CREATE INDEX users_imported_idx ON users (tenant_id, created_at) WHERE status = 'imported';

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['directory_connections','user_directory_links']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id))', t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON directory_connections, user_directory_links TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- DESTRUCTIVE: every user still in status 'imported' is hard-deleted (with
-- their dependent rows via ON DELETE CASCADE) so the three-value CHECK can be
-- restored. Invited/active users that came from a directory are kept; only
-- their origin link is lost with user_directory_links. users has FORCE RLS,
-- so the delete runs in system scope.
SELECT set_config('app.system', 'on', true);
DELETE FROM users WHERE status = 'imported';
DROP INDEX IF EXISTS users_imported_idx;
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('invited','active','deactivated'));
DROP TABLE IF EXISTS user_directory_links, directory_connections;
