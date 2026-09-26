# Operations

## Bootstrap

`authsvc bootstrap -config <cfg> -operator-email <addr>` is idempotent. It
applies migrations, ensures the OpenFGA store and model, creates the
`platform` tenant (MFA mandatory by policy) with its built-in roles, queues
an operator invitation (also printed as an accept link) and creates the
initial signing key. Run it once per deployment, and again whenever a new
first operator is needed.

## Email (feature 017)

auth sends no mail itself. Invitations, account resets and recovery links are
queued in the `outbox` table (sealed with the KEK, bound to the recipient) and
handed to the **notification** module over the mesh (`notification.v1.Notifier/Send`)
by template key; notification renders the text and delivers it through the
tenant's default email channel or the platform channel.

| Message | Template key | Variables |
|---|---|---|
| invitation, resend, directory activation | `auth.invite` | `link`, `valid_for` ("72 hours"), `tenant` |
| first operator (`authsvc bootstrap`) | `auth.invite` | `link`, `valid_for` ("7 days"), `tenant` |
| administrator reset (`authsvc reset-user`) | `auth.account_reset` | `link`, `valid_for` ("7 days") |
| password recovery | `auth.recovery` | `link`, `valid_for` ("30 minutes") |
| rows queued by auth ≤ 4.1 | `auth.message` | `subject`, `text` |

The wording is edited in notification (system templates); auth only supplies
the variables. The tenant of a send is the message's tenant and the
correlation id is the outbox row id, so a notification log entry can be
matched to its row.

```yaml
email:
  transport: notification   # default; log = print links to the log (development only, refused in production)
```

The relay keys of auth ≤ 4.1 (`host`, `port`, `username`, `password`,
`from`, `allow_plaintext`, and `transport: smtp`) still load, are **ignored**,
and are named in one warning at start. Remove them; they are refused in v5.
The relay is configured once, in notification (`platform_email`).

### Delivery, retries and given-up messages

The worker polls every 5 s and claims up to 50 due rows. Each claim counts an
attempt and schedules the next one 30 s · 2^attempts later, capped at one
hour. The outcome decides what happens next:

- **sent** — `sent_at` is set.
- **retry** — notification unreachable or not yet registered, throttled
  (`ResourceExhausted`), a transient relay error (SMTP 4xx, network): the row
  stays pending. Each retry logs `email delivery` at warning level.
- **failed** — a permanent answer (unknown template key, no email channel
  configured — `email_not_configured` —, SMTP 5xx, invalid recipient, relay
  certificate or TLS refusal), a payload that cannot be opened, or the 8th
  attempt without success.

A failed row is **retired**: `failed_at` and `last_error` (scrubbed, at most
200 characters) are set and it is never claimed again. The retirement is
reported **once**: a warning `email given up` (row id, tenant, kind,
attempts, reason) and an `email_given_up` audit event in the message's tenant
(subject `email` = row id; details `kind`, `attempts`, `error`). Neither
carries the recipient or the link.

To resend, issue a new invitation/reset/recovery; the link in a given-up row
is not recoverable (it is sealed and the token is stored hashed). Rows that
auth ≤ 4.1 had already tried more than 8 times are retired, and reported, on
their first claim after the upgrade.

```sql
-- Given-up messages (system scope)
SELECT id, tenant_id, kind, attempts, failed_at, last_error FROM outbox
WHERE failed_at IS NOT NULL ORDER BY failed_at DESC LIMIT 50;
```

Development configurations (`deploy/dev*.yaml`, `deploy/gateway-mode.yaml`)
use `transport: log`: every message, link included, is printed as
`email (dev sink)`.

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

## Authenticator label

`mfa.issuer` (default `Tangra`) is the name authenticator apps show next to
the account. It is written into the `otpauth://` URI at enrolment only; codes
depend on the seed alone, so changing it never breaks enrolled authenticators
(they keep the label they were enrolled with).

## Security keys (feature 018)

Users can register hardware security keys (YubiKey and other FIDO2/WebAuthn
authenticators) as a second factor next to the authenticator app: up to 10
named keys per user, managed under Account → Second factors. The first
second factor of any kind issues ten recovery codes; recovery codes remain
the shared fallback for both kinds. Migration `0010_webauthn.sql` adds the
`webauthn_credentials` table (RLS like `recovery_codes`) and
`users.webauthn_handle` (32 random bytes, never the user id).

### Configuration (`webauthn`)

```yaml
webauthn:
  enabled: true                 # default: on unless the issuer host is an IP address
  rp_id: ""                     # default: host of `issuer`
  origins: []                   # default: [origin of `issuer`] (port kept unless 443)
  display_name: ""              # default: mfa.issuer ("Tangra")
  user_verification: preferred  # preferred | required (key PIN or biometric)
  timeout_seconds: 300          # 30..600; also the lifetime of a pending ceremony
```

No change is needed in a deployment: the relying party is derived from
`issuer` (production `https://portal.infra.verax.net:8443` → relying party
`portal.infra.verax.net`, origin `https://portal.infra.verax.net:8443`). The
service refuses to start when `rp_id` is neither an origin's host nor a
parent domain of it, when an origin is not `https://` (plain
`http://localhost` is accepted outside production), or when
`user_verification` / `timeout_seconds` are out of range. With
`webauthn.enabled: false` the routes answer `404 webauthn_disabled`, the
second step no longer offers keys, and a warning is logged at start if users
still have keys registered (they then sign in with the authenticator app or a
recovery code).

### Keys are bound to the public host name

Browsers bind every key to the relying party. Consequences:

- The console must be opened under the configured host name. Opened by IP
  address or another name, adding a key and signing in with one are refused
  (the console names the expected address).
- **Changing the public host name (new domain) invalidates every registered
  key.** Users sign in with the authenticator app or a recovery code, remove
  the old keys and register them again; an administrator can reset users who
  have neither (below). Plan a host change like a key rotation and tell users
  beforehand.
- v3 key registrations are not migrated (different relying party and user
  handles): users register their keys again in v4.

### Administrators and break-glass

- `GET /api/v1/admin/users/{id}/mfa` (console: Users → user → Second
  factors) shows whether an authenticator app is set, the key names, when they
  were added and last used, whether one is flagged as possibly cloned, and the
  number of unused recovery codes — never credential ids or key material.
- `POST /api/v1/admin/users/{id}/mfa/reset` (`users:manage`) removes the
  authenticator app, every key and every recovery code, ends the user's
  sessions and is audited as `mfa_reset`. The same rules as deactivation
  apply: not your own account, not a more privileged user. A tenant that
  requires two-step sign-in (the platform tenant always does) asks the user
  to set up a second factor at the next sign-in.
- `authsvc reset-user` (break-glass, see Bootstrap) also deletes the user's
  keys.

### Audit and signals

`mfa_enrolled` / `mfa_removed` carry `method: "webauthn"` (and the model
AAGUID on enrolment); `signin_ok` records `amr: ["pwd","hwk"]`; a signature
counter that did not increase refuses the sign-in, flags the key and writes
`mfa_clone_suspected` — investigate the user's key, then have them remove
and re-register it. Key failures count toward the same lockout as wrong
codes (`signin_failed` reason `mfa_failed`, `lockout` reason
`mfa_failures`).

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

`env: production` refuses plaintext Valkey/OpenFGA, weak `sslmode`, a
missing edge certificate, a dev KEK and `email.transport: log`. The ignored
email relay keys are warned about, not refused (see Email). Warnings (not failures) are logged for
loopback listeners, permissive CORS origins, `directory.allow_plaintext` and
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
  allow_plaintext: false        # ldap:// without TLS (bind password in clear text); warned at start
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
  (any environment, warned at start). The bind password then crosses the
  network in clear text: use it only for a directory that offers neither
  LDAPS nor StartTLS, on a network you trust.
  This is also checked on every use: once the opt-out is removed, tests,
  searches and imports on existing plain connections fail with
  `insecure_transport`.
- Editing a connection keeps its stored bind password, unless the edit
  changes `url`, `tls_mode` or `ca_pem`. Those edits (and unsaved tests
  that change them) need the password again and otherwise fail with
  `validation_failed`.
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
