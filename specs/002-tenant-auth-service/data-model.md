# Data Model: Multi-Tenant Authentication & Authorization Service

**Feature**: 002-tenant-auth-service | **Date**: 2026-09-15

Storage: TimescaleDB (PostgreSQL 16). Every tenant-owned table has `tenant_id` and a
row-level-security policy `tenant_id = current_setting('app.tenant_id')::uuid`
(operator paths use `app.operator_grant`). Identifiers are UUIDv7. Times are
`timestamptz`. Secrets are never stored in plaintext.

## tenants

| Column | Type | Rules |
|--------|------|-------|
| id | uuid PK | |
| slug | text UNIQUE | `^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`; immutable |
| display_name | text | 1..120 chars |
| status | enum `active`/`suspended` | suspension ends all sessions (FR-004) |
| policy | jsonb | see SecurityPolicy |
| kind | enum `customer`/`platform` | exactly one `platform` tenant (operators) |
| created_at, updated_at | timestamptz | |

**SecurityPolicy (jsonb, validated)**: `session_lifetime` (≤ 24h, default 8h),
`idle_timeout` (≤ session_lifetime, default 1h), `access_token_lifetime` (≤ 15m),
`password_min_length` (≥ 8, default 12), `mfa_required` (bool, default false;
forced true for `platform`), `lockout_threshold` (3..20, default 10),
`lockout_duration` (1m..1h, default 15m).

## users

| Column | Type | Rules |
|--------|------|-------|
| id | uuid PK | globally unique, opaque |
| tenant_id | uuid FK tenants | |
| email | citext | UNIQUE (tenant_id, email); never unique across tenants |
| display_name | text | |
| status | enum `invited`/`active`/`deactivated` | `locked` is derived from Valkey `lock:<uid>` |
| password_hash | text | argon2id string; NULL while `invited` |
| password_changed_at | timestamptz | |
| mfa_enabled | bool | |
| mfa_secret_enc | bytea | envelope-encrypted TOTP seed; NULL when disabled |
| mfa_last_counter | bigint | replay protection |
| created_at, updated_at, last_signin_at | timestamptz | |

**Transitions**: `invited → active` (invitation accepted); `active ↔ deactivated`
(admin); any state → row removal only via GDPR tooling (out of scope). Deactivation
revokes all sessions and denies all decisions (FR-016).

## recovery_codes

| Column | Type | Rules |
|--------|------|-------|
| user_id | uuid FK | |
| code_hash | text | argon2id; single use |
| used_at | timestamptz | NULL until used |

## roles

| Column | Type | Rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid FK | |
| slug | text | UNIQUE (tenant_id, slug); built-ins `owner`, `admin`, `member` are `builtin=true` and immutable |
| display_name | text | |
| builtin | bool | |
| created_at, updated_at | timestamptz | |

Role membership and permission grants are **authoritative in OpenFGA**
(`role:<tid>/<slug>#assignee`, `permission:<tid>/<res>~<act>#granted`); the
`role_bindings` and `role_permissions` tables mirror them for listing and rebuild.

## role_bindings (mirror)

| user_id | role_id | tenant_id | granted_by | granted_at |

## permissions (registry, FR-015)

| Column | Type | Rules |
|--------|------|-------|
| tenant_id | uuid FK | permissions are registered per tenant (services register into every tenant they serve, or `*` handled by the registry expanding to all tenants) |
| resource | text | `^[a-z][a-z0-9_-]{0,63}$` |
| action | text | `^[a-z][a-z0-9_-]{0,31}$` |
| description | text | |
| registered_by | text | SPIFFE ID of the registering service |
| PK | (tenant_id, resource, action) | |

## role_permissions (mirror)

| role_id | tenant_id | resource | action |

## sessions

| Column | Type | Rules |
|--------|------|-------|
| id | uuid PK (`sid`) | the cookie holds a separate 256-bit random secret whose hash is `secret_hash` |
| tenant_id, user_id | uuid FK | |
| secret_hash | bytea | SHA-256 of the cookie value |
| amr | text[] | `pwd`, `otp` |
| created_at, last_seen_at, expires_at | timestamptz | `expires_at = created_at + session_lifetime` |
| ip_hash, user_agent | text | origin for the audit trail (IP hashed with a daily salt) |
| revoked_at, revoked_reason | timestamptz, enum `signout`/`admin`/`password_change`/`deactivated`/`tenant_suspended`/`expired` | |

Live state mirrors in Valkey `sess:<sid>` (TTL = idle timeout).

## signing_keys

| Column | Type | Rules |
|--------|------|-------|
| kid | text PK | |
| public_key | bytea | Ed25519 |
| private_key_enc | bytea | envelope-encrypted (DEK per key, KEK from secrets provider) |
| state | enum `active`/`retiring`/`retired` | exactly one `active` |
| created_at, retiring_at, retired_at | timestamptz | published while `active`/`retiring`/`retired` and any issued token may still be valid |

## revocations (hypertable, 1 h retention)

| ts | kind (`session`/`user`/`tenant`) | subject_id | tenant_id | reason |

Feed cursor = `ts`. Downstream services reject tokens whose `sid`/`sub`/`tid` matches
an entry with `ts ≥ token.iat`.

## invitations

| Column | Type | Rules |
|--------|------|-------|
| id | uuid PK | |
| tenant_id | uuid FK | |
| email | citext | |
| role_ids | uuid[] | |
| token_hash | bytea | SHA-256 of the emailed token; single use |
| invited_by | uuid | |
| expires_at | timestamptz | default 72 h |
| accepted_at, revoked_at | timestamptz | |

## recovery_requests

| id | tenant_id | user_id | token_hash | expires_at (default 30 min) | used_at | requested_ip_hash |

## client_applications (FR-023)

| Column | Type | Rules |
|--------|------|-------|
| client_id | text PK | |
| tenant_id | uuid FK | |
| display_name | text | |
| redirect_uris | text[] | exact match, https only (http://127.0.0.1 allowed when env ≠ production) |
| public | bool | PKCE required for all; confidential clients also present a secret hash |
| secret_hash | text | argon2id; NULL for public clients |

## authorization_codes (short-lived; Valkey with 60 s TTL, no table)

`code_hash → {client_id, tenant_id, user_id, sid, code_challenge, redirect_uri, scope}`

## operator_grants (SR-006)

| id | operator_user_id | tenant_id | reason | granted_at | expires_at (≤ 4 h) | revoked_at |

## auth_audit_events (hypertable; 400 d retention; no compression — TimescaleDB forbids it together with row-level security)

| Column | Type |
|--------|------|
| ts | timestamptz |
| tenant_id | uuid |
| event_type | text (closed vocabulary: `signin_ok`, `signin_failed`, `lockout`, `signout`, `mfa_enrolled`, `mfa_removed`, `recovery_codes_regenerated`, `password_changed`, `recovery_requested`, `recovery_completed`, `invite_created`, `invite_accepted`, `invite_revoked`, `role_created`, `role_updated`, `role_deleted`, `role_assigned`, `role_revoked`, `permission_registered`, `user_deactivated`, `user_reactivated`, `session_revoked`, `tenant_created`, `tenant_suspended`, `tenant_reactivated`, `operator_grant_created`, `operator_grant_used`, `client_registered`, `policy_updated`, `cross_tenant_refused`, `authz_denied`, `token_exchanged`) |
| actor_user_id, actor_kind (`user`/`operator`/`service`/`system`) | uuid, text |
| actor_service | text (SPIFFE ID when a service acted) |
| subject_kind, subject_id | text, uuid |
| outcome | text (`ok`/`refused`/`failed`) |
| reason | text (closed vocabulary) |
| origin_ip_hash, user_agent | text |
| correlation_id, trace_id | text |
| details | jsonb (redacted; never secrets) |

Indexes: `(tenant_id, ts desc)`, `(tenant_id, subject_id, ts desc)`,
`(tenant_id, event_type, ts desc)`.

## signin_attempts (hypertable; 30 d retention)

| ts | tenant_id | user_id (nullable) | email_hash | ip_hash | outcome | reason |

## outbox (email)

| id | tenant_id | kind (`invite`/`recovery`) | to_email | payload_enc | attempts | next_attempt_at | sent_at |

## Valkey keys

| Key | Type / TTL | Purpose |
|-----|------------|---------|
| `sess:<sid>` | hash, idle timeout | live session state |
| `rev:sid:<sid>`, `rev:user:<uid>`, `rev:tenant:<tid>` | string ts, max token lifetime + skew | revocation marks |
| `lock:<uid>` | string, lockout duration | account lockout |
| `rl:signin:ip:<hash>`, `rl:signin:user:<uid>`, `rl:recovery:ip:<hash>` | counters, window | rate limits |
| `dec:<tid>:<uid>:<perm>` | string, 2 s | decision cache |
| `tenantver:<tid>` | int | bumped on role/permission change to bust caches |
| `code:<hash>` | hash, 60 s | authorization codes |
| channel `auth:revoked` | pub/sub | fan-out to instances |

## OpenFGA objects (see contracts/authorization-model.fga)

- `tenant:<tid>` — `owner`, `admin`, `member`
- `role:<tid>/<slug>` — `tenant`, `assignee`
- `permission:<tid>/<resource>~<action>` — `tenant`, `granted`

Invariant: every object id starts with the tenant id, and the service refuses any
check/write whose object tenant ≠ caller's tenant context (SR-001).
