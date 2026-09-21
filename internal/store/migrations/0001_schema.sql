-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE tenants (
  id            uuid PRIMARY KEY,
  slug          text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$'),
  display_name  text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  status        text NOT NULL CHECK (status IN ('active','suspended')),
  kind          text NOT NULL CHECK (kind IN ('customer','platform')),
  policy        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tenants_single_platform ON tenants ((kind)) WHERE kind = 'platform';

CREATE TABLE users (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenants(id),
  email               citext NOT NULL,
  display_name        text NOT NULL DEFAULT '',
  status              text NOT NULL CHECK (status IN ('invited','active','deactivated')),
  password_hash       text,
  password_changed_at timestamptz,
  mfa_enabled         boolean NOT NULL DEFAULT false,
  mfa_secret_enc      bytea,
  mfa_last_counter    bigint NOT NULL DEFAULT 0,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  last_signin_at      timestamptz,
  UNIQUE (tenant_id, email)
);

CREATE TABLE recovery_codes (
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  code_hash text NOT NULL,
  used_at   timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE roles (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  slug         text NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  display_name text NOT NULL,
  builtin      boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug)
);

CREATE TABLE role_bindings (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL,
  granted_by uuid,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE permissions (
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  resource      text NOT NULL CHECK (resource ~ '^[a-z][a-z0-9_-]{0,63}$'),
  action        text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_-]{0,31}$'),
  description   text NOT NULL DEFAULT '',
  registered_by text NOT NULL,
  PRIMARY KEY (tenant_id, resource, action)
);

CREATE TABLE role_permissions (
  role_id   uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  resource  text NOT NULL,
  action    text NOT NULL,
  PRIMARY KEY (role_id, resource, action)
);

CREATE TABLE sessions (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret_hash    bytea NOT NULL,
  amr            text[] NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  ip_hash        text NOT NULL DEFAULT '',
  user_agent     text NOT NULL DEFAULT '',
  revoked_at     timestamptz,
  revoked_reason text CHECK (revoked_reason IS NULL OR revoked_reason IN ('signout','admin','password_change','deactivated','tenant_suspended','expired'))
);
CREATE INDEX sessions_user_idx ON sessions (tenant_id, user_id, created_at DESC);

CREATE TABLE signing_keys (
  kid             text PRIMARY KEY,
  public_key      bytea NOT NULL,
  private_key_enc bytea NOT NULL,
  state           text NOT NULL CHECK (state IN ('active','retiring','retired')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  retiring_at     timestamptz,
  retired_at      timestamptz
);
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys ((state)) WHERE state = 'active';

CREATE TABLE invitations (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  email       citext NOT NULL,
  role_ids    uuid[] NOT NULL DEFAULT '{}',
  token_hash  text NOT NULL UNIQUE,
  invited_by  uuid,
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recovery_requests (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash        text NOT NULL UNIQUE,
  expires_at        timestamptz NOT NULL,
  used_at           timestamptz,
  requested_ip_hash text NOT NULL DEFAULT ''
);

CREATE TABLE client_applications (
  client_id     text PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  display_name  text NOT NULL,
  redirect_uris text[] NOT NULL,
  public        boolean NOT NULL DEFAULT true,
  secret_hash   text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operator_grants (
  id               uuid PRIMARY KEY,
  operator_user_id uuid NOT NULL,
  tenant_id        uuid NOT NULL REFERENCES tenants(id),
  reason           text NOT NULL CHECK (length(reason) >= 10),
  granted_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz
);

CREATE TABLE outbox (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('invite','recovery')),
  to_email        citext NOT NULL,
  payload_enc     bytea NOT NULL,
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX outbox_pending_idx ON outbox (next_attempt_at) WHERE sent_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS outbox, operator_grants, client_applications, recovery_requests, invitations, signing_keys, sessions, role_permissions, permissions, role_bindings, roles, recovery_codes, users, tenants;
