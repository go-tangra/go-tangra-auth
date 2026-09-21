# Operations

## Bootstrap

`authsvc bootstrap -config <cfg> -operator-email <addr>` is idempotent. It
applies migrations, ensures the OpenFGA store and model, creates the
`platform` tenant (MFA mandatory by policy) with its built-in roles, queues
an operator invitation (also printed as an accept link) and creates the
initial signing key. Run it once per deployment, and again whenever a new
first operator is needed.

## Key material

| Secret | Where | Rotation |
|--------|-------|----------|
| KEK (32 bytes, base64) | file (`kek.path`, mode 0600) or environment (`kek.env`) | re-encrypt: start with the new KEK, run `bootstrap` to mint a new signing key, re-enrol TOTP users (seeds are sealed with the KEK) |
| Signing keys (Ed25519) | `signing_keys`, private half sealed with the KEK | automatic: 24 h rotation, 30 min retiring, removed after the last token could expire; JWKS keeps every verifiable key |
| OpenFGA preshared key | `openfga.preshared_key` | rotate in OpenFGA, then in config; restart |
| Valkey ACL password | `valkey.password` | rotate in Valkey ACL, then config; the user needs key (`~*`) and channel (`&*`) access: revocations are published on Pub/Sub, and sign-out fails without it |
| Database roles | `db.dsn` (`auth_app`, **no BYPASSRLS**), `db.migrate_dsn` (owner) | standard PostgreSQL rotation |

Never point `db.dsn` at a superuser or a role with `BYPASSRLS`: row-level
security is the last line of tenant isolation.

## Groups and profiles (feature 004)

- Migration `0005_groups_profiles.sql` adds `groups`, `group_members`,
  `group_roles`, `avatars` and the profile columns; `0006_session_reasons.sql`
  aligns the session revocation vocabulary. Existing users keep their display
  names; one that merely repeats the email is treated as unset so first/last
  names take over. Nobody needs to sign in again.
- The OpenFGA model gains `type group` and `role.assignee: [user, group#member]`;
  it is written on start like every model change.
- Console permission `groups:manage` is seeded to `owner`, `admin` and
  `operator` on start (idempotent).
- Configuration (`profile`): `avatar_max_bytes` (2 MiB), `avatar_max_pixels`
  (4096²), `avatar_size` (512), `avatar_decode_concurrency` (4),
  `lookup_rate_per_minute` (120). Raise `limits.max_request_bytes` to at least
  `avatar_max_bytes` + 64 KiB (the dev configs use 2162688); the framework logs
  the raised limit at start.
- Avatars are stored in the `avatars` table (≈ 20–120 KiB each); size backups
  accordingly.

## OpenFGA

The service creates the store (`auth`) and writes the authorization model on
start when `openfga.store_id` is empty; set `store_id` in production to pin
the store. The model never changes at runtime; a model change ships as a new
service version that writes a new model id on start.

## Backups and retention

- TimescaleDB: back up the whole database (`pg_dump` or physical). Audit
  events are a hypertable with 400-day retention (no compression: TimescaleDB
  does not allow it on row-level-secured hypertables);
  sign-in attempts keep 30 days; revocations keep 60 minutes.
- Valkey holds only derived state (session projections, revocation marks,
  counters, decision cache, pending challenges). Losing it forces users to
  re-authenticate at most once and clears rate-limit windows; it never loses
  sessions or audit data.
- OpenFGA tuples are mirrored in `role_bindings`, `role_permissions` and
  `permissions`; a rebuild can replay them into a fresh store.

## Health

- Admin listener: readiness, liveness and metrics (Freya).
- `GET /.well-known/jwks.json` must always return at least one `active` key.
- The revocation feed must advance (`auth.v1.Sessions/RevokedSince`); a
  verifier that cannot sync for 60 minutes fails closed by design.

## Configuration checks in production

`env: production` refuses plaintext Valkey/OpenFGA/SMTP, weak `sslmode`, a
missing edge certificate and a dev KEK. Warnings (not failures) are logged for
loopback listeners and permissive CORS origins.

## Member-level lookups and module role grants (feature 005)

`GET /api/v1/users?q=` (public profiles of active members matching name or
email, at most 20, sharing the lookup rate limit) and `GET /api/v1/roles`
(slug and display name) serve subject pickers of other modules. Modules may
pass `builtin_grants` to `Authorization/RegisterPermissions` to grant their
own freshly registered permissions to built-in roles; grants naming foreign
permissions or custom roles are refused.
