-- +goose Up
-- Feature 018: security keys (WebAuthn) as a second factor. One row per
-- registered credential; the user handle given to authenticators is a random
-- 32-byte value per user (never the user id, WebAuthn §14.6.1).
ALTER TABLE users ADD COLUMN webauthn_handle bytea UNIQUE
  CHECK (webauthn_handle IS NULL OR octet_length(webauthn_handle) = 32);

CREATE TABLE webauthn_credentials (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id    bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  public_key       bytea NOT NULL CHECK (octet_length(public_key) <= 2048),
  sign_count       bigint NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
  aaguid           bytea CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
  transports       text[] NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
  backup_eligible  boolean NOT NULL DEFAULT false,
  backup_state     boolean NOT NULL DEFAULT false,
  name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_used_at     timestamptz,
  clone_flagged_at timestamptz
);
CREATE UNIQUE INDEX webauthn_credentials_user_name ON webauthn_credentials (user_id, lower(name));
CREATE INDEX webauthn_credentials_tenant_user ON webauthn_credentials (tenant_id, user_id);

-- +goose StatementBegin
DO $$
BEGIN
  ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
  ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
  CREATE POLICY tenant_isolation ON webauthn_credentials USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id));
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials TO auth_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only in deployments (platform convention); kept for test resets.
DROP TABLE IF EXISTS webauthn_credentials;
ALTER TABLE users DROP COLUMN IF EXISTS webauthn_handle;
