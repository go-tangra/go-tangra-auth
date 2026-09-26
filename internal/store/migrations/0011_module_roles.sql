-- +goose Up
-- Feature 019: module-scoped permissions and module roles.

-- Platform catalogue (system scope: readable in every scope, written only with
-- app.system). Registrations upsert it; tenant creation instantiates it.
CREATE TABLE modules (
  name          text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
  display_name  text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  registered_at timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  retired_at    timestamptz
);

CREATE TABLE module_permissions (
  module      text NOT NULL REFERENCES modules(name),
  resource    text NOT NULL CHECK (resource ~ '^[a-z][a-z0-9_-]{0,63}$'),
  action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_-]{0,31}$'),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  retired_at  timestamptz,
  PRIMARY KEY (module, resource, action)
);

CREATE TABLE module_role_defs (
  module       text NOT NULL REFERENCES modules(name),
  slug         text NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  description  text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  permissions  text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 200),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  retired_at   timestamptz,
  PRIMARY KEY (module, slug)
);

-- Per-tenant module state; legacy_migrated_at is the access-preserving
-- migration marker, set only after the OpenFGA write succeeded.
CREATE TABLE tenant_modules (
  tenant_id           uuid NOT NULL REFERENCES tenants(id),
  module              text NOT NULL REFERENCES modules(name),
  first_registered_at timestamptz NOT NULL DEFAULT now(),
  legacy_migrated_at  timestamptz,
  PRIMARY KEY (tenant_id, module)
);

-- Permissions become module-scoped; existing rows are legacy (module = '').
ALTER TABLE permissions ADD COLUMN module text NOT NULL DEFAULT ''
  CONSTRAINT permissions_module_check CHECK (module = '' OR module ~ '^[a-z][a-z0-9-]{0,31}$');
ALTER TABLE permissions DROP CONSTRAINT permissions_pkey,
  ADD PRIMARY KEY (tenant_id, module, resource, action);

ALTER TABLE role_permissions ADD COLUMN module text NOT NULL DEFAULT ''
  CONSTRAINT role_permissions_module_check CHECK (module = '' OR module ~ '^[a-z][a-z0-9-]{0,31}$');
ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_pkey,
  ADD PRIMARY KEY (role_id, module, resource, action);

-- Roles gain origin and module identity.
ALTER TABLE roles
  ADD COLUMN origin      text NOT NULL DEFAULT 'custom' CHECK (origin IN ('builtin','module','custom')),
  ADD COLUMN module      text,
  ADD COLUMN module_slug text,
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  ADD COLUMN retired_at  timestamptz;
UPDATE roles SET origin = 'builtin' WHERE builtin;
ALTER TABLE roles DROP CONSTRAINT roles_slug_check,
  ADD CONSTRAINT roles_slug_check CHECK (
    (origin <> 'module' AND slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    OR (origin = 'module' AND slug = 'm.' || module || '.' || module_slug)),
  ADD CONSTRAINT roles_module_identity CHECK (
    (origin = 'module') = (module IS NOT NULL AND module_slug IS NOT NULL)),
  ADD CONSTRAINT roles_builtin_origin CHECK (builtin = (origin = 'builtin')),
  ADD CONSTRAINT roles_retired_module CHECK (retired_at IS NULL OR origin = 'module');
CREATE UNIQUE INDEX roles_module_slug ON roles (tenant_id, module, module_slug) WHERE origin = 'module';
CREATE INDEX permissions_legacy ON permissions (tenant_id, resource, action) WHERE module = '';

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  ALTER TABLE tenant_modules ENABLE ROW LEVEL SECURITY;
  ALTER TABLE tenant_modules FORCE ROW LEVEL SECURITY;
  CREATE POLICY tenant_isolation ON tenant_modules USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id));
  FOREACH t IN ARRAY ARRAY['modules','module_permissions','module_role_defs']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY catalogue_read ON %I FOR SELECT USING (true)', t);
    EXECUTE format('CREATE POLICY catalogue_write ON %I FOR ALL USING (current_setting(''app.system'', true) = ''on'') WITH CHECK (current_setting(''app.system'', true) = ''on'')', t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, UPDATE ON modules, module_permissions, module_role_defs, tenant_modules TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only (platform convention).
SELECT 1;
