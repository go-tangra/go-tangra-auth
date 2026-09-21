-- +goose Up
-- Feature 004: flat groups carrying roles, user profiles and avatars.

CREATE TABLE groups (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_tenant_name ON groups (tenant_id, lower(name));

CREATE TABLE group_members (
  group_id  uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  added_by  uuid,
  added_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_tenant_user ON group_members (tenant_id, user_id);

CREATE TABLE group_roles (
  group_id   uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL,
  granted_by uuid,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, role_id)
);

CREATE TABLE avatars (
  id           text PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content_type text NOT NULL,
  bytes        bytea NOT NULL,
  size         integer NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id)
);

ALTER TABLE users
  ADD COLUMN first_name            text NOT NULL DEFAULT '',
  ADD COLUMN last_name             text NOT NULL DEFAULT '',
  ADD COLUMN phone                 text NOT NULL DEFAULT '',
  ADD COLUMN avatar_id             text REFERENCES avatars(id) ON DELETE SET NULL,
  ADD COLUMN display_name_explicit boolean NOT NULL DEFAULT true,
  ADD COLUMN profile_updated_at    timestamptz;

-- Existing users keep their display name; one that merely repeats the email
-- (the legacy default) is not explicit, so first/last names take over later.
UPDATE users SET display_name_explicit = (display_name <> '' AND display_name <> email AND display_name <> split_part(email, '@', 1));

ALTER TABLE invitations
  ADD COLUMN group_ids  uuid[] NOT NULL DEFAULT '{}',
  ADD COLUMN first_name text NOT NULL DEFAULT '',
  ADD COLUMN last_name  text NOT NULL DEFAULT '';

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['groups','group_members','group_roles','avatars']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id))', t);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON groups, group_members, group_roles, avatars TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE invitations DROP COLUMN group_ids, DROP COLUMN first_name, DROP COLUMN last_name;
ALTER TABLE users DROP COLUMN first_name, DROP COLUMN last_name, DROP COLUMN phone, DROP COLUMN avatar_id, DROP COLUMN display_name_explicit, DROP COLUMN profile_updated_at;
DROP TABLE IF EXISTS avatars, group_roles, group_members, groups;
