# Data Model: Security Keys (018)

## Migration `internal/store/migrations/0010_webauthn.sql`

```sql
-- +goose Up
ALTER TABLE users ADD COLUMN webauthn_handle bytea UNIQUE
  CHECK (webauthn_handle IS NULL OR octet_length(webauthn_handle) = 32);

CREATE TABLE webauthn_credentials (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id    bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  public_key       bytea NOT NULL CHECK (octet_length(public_key) <= 2048),
  sign_count       bigint NOT NULL DEFAULT 0,
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
-- RLS: same tenant policy as recovery_codes (0003_rls.sql pattern); grants to auth_app.
```

Forward-only (platform convention).

## Entities

### SecurityKey (`store.WebAuthnCredential`)
| Field | Rule |
|---|---|
| id | uuid (store.NewID) |
| tenant_id, user_id | owner; cascade on user delete |
| credential_id | raw bytes from the authenticator; unique globally |
| public_key | COSE key bytes |
| sign_count | updated on every successful assertion |
| aaguid, transports, backup_* | from registration / assertion |
| name | 1–64 chars, unique per user (case-insensitive) |
| last_used_at | set on successful sign-in or step-up |
| clone_flagged_at | set on counter regression; flagged keys are refused |

Limit: ≤ 10 keys per user (service check).

### User (extended)
| Field | Rule |
|---|---|
| webauthn_handle | 32 random bytes, created on first registration, stable |
| mfa_enabled | true when TOTP or ≥ 1 key exists |

### Ceremony records (Valkey, JSON, 5 min, GETDEL)
| Key | Value |
|---|---|
| `challenge:webauthn:reg:<uid>` | `{session, name, tenant_id}` |
| `challenge:webauthn:signin:<sha256(mfa challenge id)>` | `{session, user_id, tenant_id}` |
| `challenge:webauthn:stepup:<uid>` | `{session, purpose: "remove"}` |

## State

`none` → (first TOTP or key) → `protected` (mfa_enabled, recovery codes
issued) → (last factor removed, policy optional) → `none` (codes deleted).
Admin reset: any → `none` + sessions revoked.
