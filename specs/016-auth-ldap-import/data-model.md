# Phase 1 Data Model: LDAP User Import (services/auth)

One new goose migration `services/auth/internal/store/migrations/0008_ldap_import.sql`
on the existing auth database. Conventions follow migrations 0001–0007: ids are
application-generated UUIDs (`store.NewID()`), `timestamptz` timestamps, short
lower-case text enums with CHECK constraints, every tenant table has
`tenant_id uuid NOT NULL` and the `tenant_isolation` RLS policy
(`app_tenant_matches(tenant_id)`, ENABLE + FORCE), grants to `auth_app` inside a
`DO $$ … IF EXISTS (pg_roles 'auth_app')` block. Research references: D4
(sealing), D6 (filters), D8 (import), D10 (status), D13 (deletes).

## Entities

### directory_connections  (new; RLS)
| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid NOT NULL → tenants(id) | RLS key |
| `name` | text NOT NULL | 1..80 chars; unique per tenant case-insensitively |
| `kind` | text NOT NULL | `active_directory` \| `openldap` \| `other` (mapping presets only) |
| `url` | text NOT NULL | `ldap://host[:port]` or `ldaps://host[:port]`; no userinfo/path/query; ≤ 512 |
| `tls_mode` | text NOT NULL | `ldaps` \| `starttls` \| `plain` (plain: dev only — enforced in code, D3) |
| `allow_tls12` | boolean NOT NULL DEFAULT false | explicit per-connection TLS 1.2 opt-out |
| `ca_pem` | text NULL | trusted CA bundle, ≤ 64 KiB, must parse |
| `bind_dn` | text NOT NULL | ≤ 1024, must parse as a DN |
| `bind_password_enc` | bytea NOT NULL | `crypto.Envelope` ciphertext, AD `ldap-bind:<tenant_id>:<id>`; never selected into API views |
| `base_dn` | text NOT NULL | ≤ 1024, must parse as a DN |
| `base_filter` | text NOT NULL DEFAULT '' | canonical (`DecompileFilter`) RFC 4515 filter or empty; ≤ 4096 |
| `attr_uid` | text NOT NULL | e.g. `objectGUID` / `entryUUID` |
| `attr_email` | text NOT NULL | default `mail` |
| `attr_display_name` | text NOT NULL | `displayName` / `cn` |
| `attr_first_name` | text NOT NULL DEFAULT '' | optional, default `givenName` |
| `attr_last_name` | text NOT NULL DEFAULT '' | optional, default `sn` |
| `size_limit` | int NOT NULL DEFAULT 500 | CHECK 1..1000 (config may lower) |
| `time_limit_seconds` | int NOT NULL DEFAULT 15 | CHECK 1..60 |
| `last_test_at` | timestamptz NULL | |
| `last_test_outcome` | text NULL | `ok` \| `unreachable` \| `target_refused` \| `timeout` \| `tls_failed` \| `invalid_credentials` \| `base_not_found` \| `directory_error` |
| `created_by`, `updated_by` | uuid NULL | actor user ids |
| `created_at`, `updated_at` | timestamptz NOT NULL DEFAULT now() | |

- **Unique**: `(tenant_id, lower(name))`.
- Attribute columns CHECK `~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'` (or empty for the
  optional ones) — they are placed into the attribute list of a search, never
  into a filter string except through `ldap.EscapeFilter` (D8 re-fetch).
- Per-tenant count cap (`directory.max_connections_per_tenant`) enforced in the
  service on insert.

### users  (changed)
- CHECK constraint replaced:
  `status IN ('invited','active','deactivated','imported')`
  (`ALTER TABLE users DROP CONSTRAINT users_status_check; ADD CONSTRAINT …` —
  verify the generated constraint name in the migration test).
- No new columns: `imported` rows have `password_hash NULL`, `mfa_enabled
  false`, `last_signin_at NULL`; names come from the directory mapping
  (`first_name`, `last_name`, `display_name`, `display_name_explicit =
  display name attribute present`).
- `UNIQUE (tenant_id, email)` unchanged — it is the final arbiter for
  `email_in_use` races during import.
- New partial index `users_imported_idx ON users (tenant_id, created_at) WHERE
  status = 'imported'` (status filter in the users list).

### user_directory_links  (new; RLS)
| Column | Type | Notes |
|---|---|---|
| `user_id` | uuid PK → users(id) ON DELETE CASCADE | one directory origin per user |
| `tenant_id` | uuid NOT NULL | RLS key |
| `connection_id` | uuid NULL → directory_connections(id) ON DELETE SET NULL | connection deletion keeps users (US1-4) |
| `connection_name` | text NOT NULL | snapshot for display after deletion |
| `directory_uid` | text NOT NULL | ≤ 256; canonical (GUID lower-case string for AD) |
| `directory_dn` | text NOT NULL | ≤ 1024; last seen DN (display/diagnostics) |
| `first_imported_at`, `last_imported_at` | timestamptz NOT NULL | "last import time" edge case |
| `imported_by` | uuid NULL | last importing actor |

- **Unique**: `(tenant_id, connection_id, directory_uid)` — the idempotency key
  (FR-006, SC-004). Rows whose connection was deleted have `connection_id
  NULL` and no longer collide (a re-created connection is a new source; the
  `users (tenant_id, email)` unique still prevents duplicate people).
- Index `(tenant_id, connection_id)`.

### Import run / search records
No table. An "import run" (spec Key Entity) is represented by audit events in
the existing `auth_audit_events` hypertable (append-only, RLS, retention 400 d):
`directory_searched` and `directory_imported` with the details listed in
research D14. This keeps directory PII out of new storage (SR-007) and follows
YAGNI (Constitution VII).

### Invitations, outbox, role_bindings, group_members  (unchanged schema)
Activation writes the existing `invitations` row (`email`, `role_ids`,
`group_ids`, `first_name`, `last_name` from the user) and an `outbox` row of
kind `invite`. Code-level change: `store.AddGroupMembers` adds
`AND u.status <> 'imported'` to its user subquery.

### Migration grants
```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_connections, user_directory_links TO auth_app;
```
RLS enabled + forced on both tables with the standard `tenant_isolation`
policy. Down migration: drop both tables, restore the three-value CHECK only
after `DELETE FROM users WHERE status = 'imported'` (documented as destructive).

## State transitions (users.status)

```
                (import, no email sent)
   [none] ───────────────────────────────▶ imported
                                             │  │
         activate (invite perm) / plain      │  │ remove-imported (hard delete,
         invite to the same e-mail           │  │ no email)
                                             ▼  ▼
                                          invited      [deleted]
                                             │
                                invite.Accept│(password + MFA per policy)
                                             ▼
                                           active ◀──reactivate── deactivated
                                             └────deactivate────────▶
```
- `imported → invited`: only `invite.Service.Activate` or `invite.CreateWith`
  for that e-mail; same transaction as the invitation insert.
- `imported → deleted`: only `remove-imported`; refused for any other status.
- `imported → active`/`deactivated`: **impossible** — `Deactivate`/`Reactivate`/
  `Accept` refuse (`invalid_state` / `invalid_token`).
- `invited → active`: unchanged `invite.Accept`. The link row persists across
  all transitions; re-import refreshes names/email only while `imported`.
- An expired invitation leaves the user `invited`; resend works as today.

## How existing paths treat `imported`
| Path | Code | Behaviour |
|---|---|---|
| Password sign-in | `internal/user/signin.go` | treated as unknown account: dummy verify, `invalid_credentials`, audit reason `unknown_account`, **no lockout counter** |
| MFA step | `CompleteMFA` | unreachable (no challenge is ever issued) |
| Password reset request | `internal/password/recovery.go` | unchanged `status == active` check → identical ack, no outbox |
| Reset completion | `Recovery.Complete` | no recovery request can exist for an imported user |
| Invitation accept | `invite.Accept` | only `invited` rows; `imported` → `invalid_token` |
| Plain invite by e-mail | `invite.CreateWith` | converts to activation (`imported → invited`) |
| Deactivate / reactivate | `internal/user/admin.go` | `invalid_state` |
| Set roles / add to group | `httpapi.setUserRoles`, `store.AddGroupMembers` | `invalid_state` / not added |
| Profile lookups (HTTP + gRPC) | `store.SearchProfiles` etc. | already `status = 'active'` only |
| Admin users list | `store.ListUsers` | visible to admins, filter `status=imported`, joined with link for origin |
| Authorization decisions | `authz.Decider` | no FGA tuples exist for imported users (written only at accept) |

## Validation rules (summary)
- URL/port/scheme/TLS mode per research D3/D5; CA PEM parses; DNs parse;
  base search DN within the connection base; filter compiled + canonical
  (D6); limits within config bounds; password non-empty on create, optional on
  update.
- Directory values after decoding: uid ≤ 256 B, email normalised with the same
  rules as `invite.normEmail` (≤ 254), names via `user.ValidateName`.
- Activation: ≤ 100 user ids, ≤ 50 groups (`invite.GroupsMax`), roles exist in
  the tenant, escalation check (D11).
