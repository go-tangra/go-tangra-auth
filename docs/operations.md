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
missing edge certificate, a dev KEK and `directory.allow_plaintext`. Warnings
(not failures) are logged for loopback listeners, permissive CORS origins and
every `directory.targets.allow_cidrs` entry.

## Member-level lookups and module role grants (feature 005)

`GET /api/v1/users?q=` (public profiles of active members matching name or
email, at most 20, sharing the lookup rate limit) and `GET /api/v1/roles`
(slug and display name) serve subject pickers of other modules. Modules may
pass `builtin_grants` to `Authorization/RegisterPermissions` to grant their
own freshly registered permissions to built-in roles; grants naming foreign
permissions or custom roles are refused.

## LDAP directory import (feature 016)

Migration `0008_ldap_import.sql` adds `directory_connections`,
`user_directory_links` and the `imported` user status. The console permission
`directory:manage` is seeded to `owner`, `admin` and `operator` on start, and
the console shows a "Directories" entry to holders. Security design:
[`security-model.md`](security-model.md#directory-import-feature-016).

### Configuration (`directory`)

```yaml
directory:
  enabled: true                 # false: routes answer 404, nav entry hidden
  allow_plaintext: false        # ldap:// without TLS; development only, refused in production
  targets:
    deny_cidrs:                 # platform-internal networks (list yours, see below)
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - fd00::/8
    allow_cidrs: []             # overrides deny_cidrs only; each entry is a start-up warning
    allowed_ports: [389, 636, 3268, 3269]
  dial_timeout: 5s              # (0, 30s]
  max_size_limit: 1000          # ceiling for a connection's size_limit, [1, 1000]
  max_time_limit: 60s           # ceiling for a connection's time_limit_seconds, [1s, 60s]
  rate_per_minute: 30           # per-tenant connection tests + searches
  max_connections_per_tenant: 10
```

The values are checked at start: CIDRs must parse, ports must be 1..65535 and
limits must be in range. An invalid section stops the service even when
`enabled: false`.

### Listing the platform CIDRs

The code always refuses loopback, link-local (including `169.254.169.254`),
unspecified and multicast addresses. Everything else is reachable unless
**you** deny it. The address checked is the one resolved at dial time, so list
networks, not hostnames:

- **Kubernetes**: the pod CIDR and the service CIDR (`kubectl cluster-info
  dump | grep -m1 -E 'cluster-cidr|service-cluster-ip-range'`, or the
  cluster's IPAM/CNI configuration).
- **Docker / compose**: every network the auth container is attached to
  (`docker network inspect <net> -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`)
  and the default address pools in `/etc/docker/daemon.json`.
- **VMs / bare metal**: the management, database and service subnets reachable
  from the auth hosts, plus any VPC range that holds platform services.

A tenant directory that lives inside a denied range (for example, an
on-premises AD reached over a VPN in `10.0.0.0/8`) needs a narrow
`allow_cidrs` entry for that directory's address only, never the whole
range. The dev stack does exactly that for its OpenLDAP container.
`allowed_ports` is the second line of defence: keeping it at the LDAP ports
keeps PostgreSQL, Valkey, OpenFGA and admin listeners out of reach even inside
an allowed range.

### Connection settings (per tenant)

- `tls_mode: ldaps` (`ldaps://`, port 636/3269) or `starttls` (`ldap://`,
  port 389/3268). The minimum is TLS 1.3. `allow_tls12` is a per-connection
  opt-in for directories that cannot do TLS 1.3 (Active Directory before
  Windows Server 2022); it allows only ECDHE + AEAD suites.
- `ca_pem` pins the CA bundle (≤ 64 KiB, PEM certificates only) instead of
  the system roots, which is the answer for private or self-signed CAs. There
  is no skip-verify.
- `tls_mode: plain` is accepted only when `directory.allow_plaintext: true`
  and the environment is not production. Use it only for the local stack.
- Bind passwords are sealed with the KEK (associated data
  `ldap-bind:<tenant>:<connection>`). **Rotating the KEK makes stored bind
  passwords unreadable**: tests and searches on those connections fail with
  an internal error (never an anonymous bind) until a tenant administrator
  re-enters the password.

### Limits and outcomes

| Limit | Value | Answer when exceeded |
|-------|-------|----------------------|
| Connections per tenant | `max_connections_per_tenant` (10) | `409 limit_reached` |
| Tests + searches per tenant | `rate_per_minute` (30) | `429 rate_limited` |
| Search size / time | per connection, ≤ `max_size_limit` / `max_time_limit` | result marked `truncated` |
| Filter | 4 KiB, depth 16, 64 components | `invalid_filter` |
| Import request | 500 unique ids | `400 validation_failed` |
| Activation request | 100 users | `400 validation_failed` |
| LDAP message | 8 MiB | session aborted |

Test and search failures are deliberately coarse (`target_refused`,
`unreachable`, `timeout`, `tls_failed`, `invalid_credentials`,
`base_not_found`, `directory_error`). The server's diagnostic text is
dropped: a `directory_error` keeps only the numeric LDAP result code, so check
the directory server's own log for the details.

### Imported users and invitations

- Imported users (`status: imported`) cannot sign in, recover a password or
  be deactivated, reactivated, given roles or added to groups. Everything else
  treats them as non-existent. They leave that state only by **activation**
  (an ordinary invitation, 72 h, resendable), by an administrator inviting
  their e-mail address, or by **remove** (hard delete, allowed only while they
  are still imported).
- Deleting a connection keeps its users. Their origin label keeps the
  connection name, and re-importing through a new connection creates new
  links.
- **Behaviour change**: plain invitations now apply the same escalation check
  as role assignment. A non-owner administrator who invites with `owner` or
  `admin`, or with any role or group carrying a permission they do not hold,
  now gets `403 self_escalation` instead of an invitation. Owners and
  platform operators are unaffected. If an administrator's scripted
  invitations start failing after the upgrade, give them the role
  themselves or have an owner send those invitations.
