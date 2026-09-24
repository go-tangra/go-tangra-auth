# Phase 0 Research: LDAP User Import for the Auth Service

Decisions resolving the Technical Context. Scope: a feature **inside the
existing auth service** (`services/auth`) — tenant-scoped LDAP directory
connections, filtered search/preview, import of people as inactive `imported`
users, and activation through the existing invitation flow. No new service, no
new mesh peer, no new gRPC surface.

Grounding (code read for this plan):
- `internal/store/migrations/0001_schema.sql` — `users.status CHECK (status IN
  ('invited','active','deactivated'))`, `UNIQUE (tenant_id, email)`;
  `0003_rls.sql` — `app_tenant_matches(tenant_id)` policy pattern;
  `0004_grants.sql`/`0005_groups_profiles.sql` — `auth_app` grants pattern.
- `internal/invite/invite.go` — `CreateWith` silently refuses (audit
  `account_exists`) when a user row exists whose status is not `invited`;
  `Accept` activates an existing `invited` row (sets password, status `active`,
  binds roles, adds groups, writes FGA tuples). **Invitations do not create a
  user row** and **do not run the self-escalation guard** on `role_ids`.
- `internal/user/signin.go` — a user found by e-mail is `known`; a wrong
  password on a known account increments the lockout counter and can return
  `423 locked`; unknown accounts never lock. `internal/password/recovery.go` —
  `Request` sends a link only for `status == "active"`.
- `internal/user/admin.go` — `Reactivate` sets **any** `deactivated` user to
  `active` (no password check).
- `internal/httpapi/admin.go` — admin routes (incl. `POST
  /api/v1/admin/invitations`) are gated by `RequireAdmin` (built-in `owner` or
  `admin` role); `pkg/authmanifest` names that capability `users:manage`
  ("Invite, deactivate and assign roles…"). `internal/authz/assign.go` holds
  the role-grant escalation rules (non-owners cannot grant `owner`/`admin` or
  permissions they lack).
- `internal/crypto/envelope.go` — KEK-wrapped per-item AES-GCM envelope with
  associated data (used for TOTP seeds, signing keys, outbox payloads).
- `internal/config/config.go` — `IsProduction()` gates dev-only opt-outs
  (`allow_plaintext` pattern + `Warnings()`).
- `console/src/views/admin/Users.vue` + `InviteDialog.vue` (a `UiDrawer`),
  `console/src/api/vocab.ts` (`userStatuses`), `router/routes.ts`
  (`meta.roles: ['owner','admin']`).

## D1. Where the feature lives
**Decision**: Inside services/auth, as two new packages plus targeted changes:
`internal/ldapdir` (the LDAP boundary: target policy + dialer, TLS config,
filter validation/combination, DN scoping, attribute mapping/decoding — pure,
security-critical, 100 % coverage gate) and `internal/directory` (domain
service: connections CRUD with sealed bind password, test, search/preview,
import, audit) with `internal/directory/directorydb` (pgx store, the existing
`<pkg>db` pattern). Activation is added to `internal/invite` so it reuses the
invitation code path verbatim.
**Rationale**: users, invitations, audit, KEK and RLS all live in auth;
another service would need a mesh API to create users — more surface, no gain.
Splitting the pure LDAP boundary from the domain service makes the parser/
policy code fuzzable and 100 %-coverable without a directory.
**Alternatives**: a separate `directory` module talking to auth over gRPC
(rejected: new trust boundary and a user-creation RPC); putting LDAP code in
`internal/user` (rejected: mixes an outbound network client into sign-in code).

## D2. LDAP client library
**Decision**: `github.com/go-ldap/ldap/v3` (MIT; with its transitive
`github.com/go-asn1-ber/asn1-ber` and `github.com/Azure/go-ntlmssp`). Pin the
latest v3.4.x at implementation, commit `go.sum`, run `govulncheck`. Use only:
`DialURL` with `DialWithDialer` + `DialWithTLSConfig`, `StartTLS`,
`SimpleBind` (never `UnauthenticatedBind`/NTLM/GSSAPI), `Search` with explicit
`SizeLimit`/`TimeLimit`/`DerefAliases=NeverDerefAliases`/attribute list,
`CompileFilter`/`DecompileFilter`, `ParseDN` + `DN.AncestorOfFold`/`EqualFold`,
`EscapeFilter` (for the fixed per-entry uniqueness probe, D8).
**Rationale**: the de-facto Go LDAP client (used by Grafana, Gitea, Vault
plugins, Dex, Authelia), actively maintained, pure Go, supports ldaps/StartTLS
with a caller-supplied `tls.Config` and `net.Dialer` (needed for the SSRF
guard, D5), and ships an RFC 4515 filter compiler we can reuse for validation
instead of writing a parser. Repo check: **not present in any `go.sum` in the
repository** today (grep of every `go.sum`), so this is a new direct dependency
for `services/auth` only.
**Alternatives**: hand-written LDAPv3/BER client (rejected: large, error-prone
security-critical parser); `github.com/nmcclain/ldap` (unmaintained fork);
shelling out to `ldapsearch` (rejected: process spawning, no typed errors).

## D3. Transport security (SR-001)
**Decision**: Connection `url` scheme `ldaps://` (implicit TLS, default port
636) or `ldap://` + mandatory StartTLS (port 389; also 3268/3269 AD global
catalog). `tls_mode` ∈ `ldaps | starttls | plain`; `plain` is refused unless
`!cfg.IsProduction() && cfg.Directory.AllowPlaintext` (dev opt-out, logged in
`Warnings()`, audited on save). The `tls.Config` is built by `ldapdir`:
`ServerName` = URL host, `RootCAs` = the connection's CA PEM (≤ 64 KiB, must
parse to ≥ 1 certificate) **or** system roots, `MinVersion` TLS 1.3 unless the
connection sets `allow_tls12` (explicit per-connection opt-out, approved AEAD
ECDHE suites only — Constitution transport rule), never
`InsecureSkipVerify` (there is no field for it). StartTLS failure aborts the
session before bind (no fallback to plaintext).
**Rationale**: Active Directory before Windows Server 2022 only offers TLS 1.2,
so a per-connection explicit opt-out is needed in practice; the constitution
allows TLS 1.2 via explicit opt-out with an approved cipher list.
**Alternatives**: global TLS 1.2 floor (rejected: weaker default for every
tenant); a skip-verify toggle for self-signed directories (rejected: the CA PEM
field covers private CAs without disabling verification).

## D4. Bind credentials at rest (SR-002)
**Decision**: Bind password sealed with auth's existing `crypto.Envelope`
(KEK-wrapped per-item DEK, AES-256-GCM) with associated data
`"ldap-bind:<tenant_id>:<connection_id>"` (a ciphertext cannot be moved to
another tenant or connection); stored in `directory_connections.bind_password_enc`.
Decrypted only inside `directory.Service` immediately before `Bind`, held in a
`[]byte` that is zeroed after use, never placed in a struct that is logged,
audited, returned or wrapped into an error. API: write-only `bind_password`
field; responses carry `bind_password_set: true`. `PUT` without the field keeps
the stored ciphertext; an empty string is refused (no anonymous binds). LDAP
server error texts are **not** passed through: errors are mapped to a closed
vocabulary (D9) so a server that echoes the bind DN/password in a diagnostic
message cannot leak it.
**Rationale**: reuse the service's existing, audited envelope and KEK instead
of a new secret store; associated data prevents ciphertext swapping.
**Alternatives**: warden secret references (rejected for now: tenant admins
enter the password in the console; warden has no tenant-admin write path);
storing in Valkey (rejected: not durable, same exposure).

## D5. Outbound target policy (SSRF, SR-004)
**Decision**: All directory dials go through `ldapdir.Dialer`, a `net.Dialer`
whose `Control` hook checks the **resolved IP and port actually being dialled**
(defeats DNS rebinding and hostname tricks) against a typed policy from config
`directory.targets`:
- **Always denied** (not overridable): unspecified, loopback (127/8, ::1),
  link-local (169.254/16 incl. cloud metadata 169.254.169.254, fe80::/10),
  multicast, IPv4-mapped forms of the above.
- **Denied by default** (`deny_cidrs`, operator-extensible): platform-internal
  networks — in the dev stack the compose network CIDR; production operators
  list their service/pod CIDRs.
- **Allow override** (`allow_cidrs`): an address inside an allow CIDR is
  permitted even if it is inside a `deny_cidrs` range (not the always-denied
  set). Used by the dev stack to reach the OpenLDAP container.
- **Ports**: `allowed_ports` default `[389, 636, 3268, 3269]`; others refused.
  This alone removes Postgres/Valkey/OpenFGA/HTTP admin ports from reach.
- URL validation at save: scheme `ldap|ldaps`, host required, no userinfo,
  path/query/fragment empty, port in `allowed_ports`; IP-literal hosts are
  pre-checked at save; hostnames are checked at dial time.
Probe-oracle minimisation: `test` and `search` report only coarse outcomes
(`unreachable`, `target_refused`, `tls_failed`, `invalid_credentials`,
`base_not_found`, `timeout`), per-tenant rate limit on test/search
(`directory.rate_per_minute`, default 30, via the existing Valkey counter
`cache.Count`), dial timeout 5 s.
**Rationale**: a tenant admin controls the URL, so without a guard the auth
service becomes a port scanner for the platform network; checking at dial time
is the only rebinding-safe place. Denying by port is cheap and very effective.
**Alternatives**: allow-list only (rejected as default: customers' directories
are unpredictable; offered as an operator option by leaving `deny_cidrs` broad
and listing `allow_cidrs`); resolving once at save (rejected: DNS rebinding).

## D6. Filter validation and combination (SR-003, SC-005)
**Decision**: `ldapdir.CompileUserFilter(s)`:
1. Length ≤ 4 KiB, valid UTF-8, no NUL; empty input → `(objectClass=*)`.
2. `ldap.CompileFilter(s)` (RFC 4515) — failure → `invalid_filter` with the
   parser's position message (the parser message contains only the filter
   the caller typed, never server data) **before any network call**.
3. Walk the compiled BER packet: nesting depth ≤ 16, ≤ 64 components,
   attribute descriptions match `^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$` or
   an OID; refuse extensible match with `:dn:` (DN-attribute matching lets a
   filter match on DN components — not needed for people search).
4. `ldap.DecompileFilter` → canonical string.
Combination: `effective = "(&" + canon(baseFilter) + canon(userFilter) + ")"`
where both halves are independently compiled canonical filters, then the
result is compiled again (belt and braces). Because each half is a complete,
balanced filter, no input can close the `&` early and add an `|` branch
(classic injection); tests assert that for every fuzzed input the combined
packet's root is an AND whose first child equals the base filter.
Base narrowing: optional `base` must parse as a DN and be equal to or a
descendant of the connection base DN (`AncestorOfFold`/`EqualFold`); scope ∈
`one|sub` only. Search runs with `NeverDerefAliases` (aliases could point
outside the base), and every returned entry DN is re-checked to be under the
base; entries outside are dropped and counted (`out_of_scope`). Referrals
(`SearchResultReference`) are ignored — go-ldap does not chase them; tests
assert none are followed.
**Rationale**: reuse the library's grammar-complete compiler instead of regex
validation; canonical re-serialisation means nothing the admin typed reaches
the server byte-for-byte.
**Alternatives**: a restricted mini-language (attribute=value pairs) — rejected
because the spec requires RFC 4515 filters; string concatenation of raw input
(rejected: injection).

## D7. Limits and hostile responses
**Decision**: Per-connection `size_limit` (1..1000, default 500) and
`time_limit_seconds` (1..60, default 15), both sent to the server and enforced
client-side: context deadline = time limit + 2 s; the search requests
`size_limit + 1` entries so truncation is detectable, and
`LDAPResultSizeLimitExceeded`/`TimeLimitExceeded` map to a result with
`truncated: true` plus whatever entries arrived (spec US2-1/US2-2). Only
mapped attributes are requested (never `*`), so photos/certificates are not
transferred. Per-value caps after decoding: unique id ≤ 256 bytes, email ≤ 254,
names ≤ 100 runes (the existing `user.ValidateName` bound), DN ≤ 1024; an
entry with an over-long value is returned with `status: invalid` and reason
`value_too_long`, never truncated silently into a different identity. The BER
packet cap `ber.MaxPacketLengthBytes` (package variable in go-asn1-ber) is set
to 8 MiB at start (verify the variable name for the pinned version). Import
requests are bounded to 500 entries per call (FR-006; SC-001 = 100 people).
**Rationale**: SC-007 (50,000-entry directory, preview < 10 s) is met by the
server-side size limit; hostile servers cannot exhaust memory.

## D8. Import semantics and idempotency (FR-005, FR-006)
**Decision**: The import request carries **directory unique ids** chosen from
the preview (not full entries). The server re-fetches each selected entry from
the directory by an exact-match filter `(&<base_filter>(<uid_attr>=<escaped
uid>))` under the base DN (so a browser cannot inject names/emails that do not
exist in the directory, and the base filter still applies), then per entry in
one transaction per entry (partial success allowed, spec US3-4 style):
- no email / invalid email → `skipped: no_email|invalid_email`;
- link exists `(tenant, connection, directory_uid)`:
  - user `imported` → refresh email/names (email only if not used by another
    tenant user) → `updated`;
  - otherwise → names untouched (platform authoritative) → `skipped: already_active`
    (counts as unchanged, spec edge case "after activation the platform email
    is authoritative");
- email belongs to another tenant user (any status) → `skipped: email_in_use`;
- duplicate email within the same request → second `skipped: duplicate_email`;
- else insert `users` row (`status='imported'`, no password, no MFA) + link
  row → `created`.
Response `{created, updated, skipped: [{uid, reason}], failed: [{uid,
reason}]}` with user ids for created/updated. No outbox row is ever written by
import (asserted in tests). Unique ids: AD `objectGUID` (16 raw bytes →
canonical lower-case GUID string, little-endian first three groups), OpenLDAP
`entryUUID` (string), or any attribute for `other` (string value, first value
only; multi-valued → `invalid`).
**Tenant user limit**: auth has no per-tenant user limit today (checked:
no such field in tenant policy). None is invented; the per-request cap (500)
bounds the blast radius. If a limit is added later, import checks it before
inserting and reports `skipped: user_limit`.
**Rationale**: re-fetching by id keeps the directory authoritative and blocks
forged imports; per-entry transactions give the counts the spec asks for.

## D9. Error vocabulary (closed)
**Decision**: `validation_failed`, `invalid_filter`, `invalid_base`,
`invalid_url`, `insecure_transport`, `invalid_ca`, `target_refused`,
`unreachable`, `timeout`, `tls_failed`, `invalid_credentials`,
`base_not_found`, `directory_error` (any other LDAP result code; the numeric
code is logged, the server's diagnostic text is dropped), `not_found`,
`duplicate` (connection name), `invalid_state` (user not `imported`),
`self_escalation`, `rate_limited`, `forbidden`. Test results carry a `step`
(`connect|tls|bind|search_base`).

## D10. Status `imported` and non-enumeration (SR-006, SC-002)
**Decision**: Migration adds `imported` to the `users.status` CHECK. Code
changes so an imported account is indistinguishable from a non-existent one:
- `user/signin.go`: `known = true` only when the row exists **and**
  `u.Status != "imported"` — otherwise the unknown-account branch runs
  (constant-time dummy verify, `unknown_account` audit reason, **no lockout
  counter**, no `423 locked` oracle). The existing wrong-password path would
  otherwise lock imported accounts and reveal them.
- `password/recovery.go`: already requires `status == "active"`; tests pin the
  imported case (same response, same timing pad, no outbox row).
- `invite.Accept`: unchanged — only `invited` rows are activated; an
  `imported` row reached without activation is refused (`invalid_token`).
- `invite.CreateWith` (plain "Invite user" by e-mail): when the e-mail belongs
  to an `imported` user, it is treated as activation of that user (status →
  `invited`, same transaction) rather than the silent `account_exists`
  refusal — so admins who type the address get the expected result.
- `user/admin.go`: `Deactivate`/`Reactivate` refuse `imported` with
  `invalid_state` — otherwise *deactivate → reactivate* would make an
  imported, password-less row `active`, and `recovery.Request` would then mail
  a reset link to someone never invited (a real bypass of FR-005).
- `setUserRoles` and group member add refuse `imported` targets
  (`invalid_state`; `store.AddGroupMembers` filters `status <> 'imported'`):
  roles/groups are chosen at activation (spec assumption).
- Profile lookups (`store.SearchProfiles`, member-id listing) already filter
  `status = 'active'` — no change; gRPC `Profiles` inherits it.
**Rationale**: the spec requires "exactly like non-existent accounts"; the
lockout and reactivate paths are the two concrete leaks found in the code.

## D11. Activation (FR-007, FR-008)
**Decision**: `invite.Service.Activate(ctx, actor, tenantID, userIDs []string,
Params{RoleIDs, GroupIDs})` — for each user id, in its own transaction:
load under tenant scope (cross-tenant → not found + `cross_tenant_refused`
audit via the existing lookup pattern) → require `status == 'imported'` else
`invalid_state` → escalation check → the same invitation creation as
`CreateWith` (token, 72 h lifetime, outbox "invite" e-mail, `invite_created`
audit with `reason: "activation"`) → `UpdateUserStatus(imported → invited)`.
Names on the invitation come from the user row. Result per user
`{user_id, outcome: invited|failed, reason}`; ≤ 100 ids per call. Acceptance is
the unchanged `invite.Accept` (`invited` row → password, `active`, roles,
groups, FGA tuples); the directory link row stays. Resend uses the existing
`POST /api/v1/admin/invitations/{id}/resend`; to make it reachable the
activation response returns each `invitation_id`, and the users list exposes
the pending invitation id for `invited` users that have one.
**Escalation**: the existing invitation path applies **no** grant check (an
admin can invite with the `owner` role). FR-008 requires activation to follow
"a caller cannot grant roles beyond their own authority", so the check in
`authz.Assigner.AssignRoles` is extracted into `authz.Assigner.MayAssign(ctx,
actor, tenantID, roleIDs)` and group grants into the existing
`Escalation.MayGrant`; both `Activate` **and** `CreateWith` call it. This
hardens plain invitations too — a behaviour change to flag to the requester
(admins can no longer invite with `owner`/`admin` unless they are owners,
matching `setUserRoles`).
**Rationale**: one invitation code path; activation cannot be weaker than
direct role assignment.
**Alternatives**: activation creating the account directly with a random
password + reset mail (rejected: spec says "standard invitation").

## D12. Permissions and gating (FR-012)
**Decision**: New manifest permission `directory:manage` ("Connect LDAP
directories, search them and import users as inactive") in
`pkg/authmanifest.Permissions`, granted in `Grants` to `owner`, `admin` and
`operator`; new ability `{manage, [DirectoryConnection]}` and nav entry
"Directories" (`/console/admin/directories`, order 802). Enforcement: auth's
admin handlers today gate on `RequireAdmin` (owner/admin role) — permissions in
the manifest drive the shell's nav/abilities. The new handlers use a new
`RequirePermission(r, az, "directory:manage")`: allowed for `owner`/`admin`
roles (built-in grant, no FGA round trip) **or** when
`authz.Client.Allowed(tenant, user, directory:manage)` is true (custom roles).
Activation and imported-user delete use exactly the gate of `POST
/api/v1/admin/invitations` (`RequireAdmin`, i.e. `users:manage`) — "the
existing invite permission".
**Rationale**: consistent with the existing naming (`<resource>:manage`);
FGA check lets tenants delegate directory import to a custom role without
full admin.
**Alternatives**: reuse `users:manage` for directories (rejected: spec asks for
a separate permission; connecting outbound systems is a distinct privilege).

## D13. Deleting imported users and connections (FR-009, US1-4)
**Decision**: `POST /api/v1/admin/users/{id}/remove-imported` hard-deletes a
user only while `status = 'imported'` (no sessions, invitations, MFA or roles
can exist); link row cascades; audit `imported_user_deleted`; no e-mail.
Deleting a connection deletes the row; `user_directory_links.connection_id` is
`ON DELETE SET NULL` and the link keeps `connection_name` (snapshot) so users
keep their origin label. Re-import after a connection is deleted and
re-created creates new links (different connection id); the email-in-use rule
prevents duplicates.

## D14. Audit (FR-011, SR-007)
**Decision**: New event types registered in `internal/audit`:
`directory_connection_created|updated|deleted`, `directory_connection_tested`,
`directory_searched` (details: connection id, canonical user filter truncated to
1 KiB, base (if narrowed), scope, result count, truncated flag),
`directory_imported` (details: connection id, counts, created/updated user ids
— no names/emails), `user_activated` is expressed as `invite_created` with
`reason: activation` + `SubjectID` user, and `imported_user_deleted`.
Outcome `refused` rows for policy refusals (`insecure_transport`,
`target_refused`, `rate_limited`, `invalid_filter`). Never: bind DN password,
entries, emails of directory people. The admin-typed filter can contain PII
(e.g. `(mail=a@b)`); it is kept because the spec requires "filter" in the audit
and the audit log is tenant-admin-readable only.

## D15. Configuration
**Decision**: New typed section `directory` in `internal/config`:
`enabled` (default true), `allow_plaintext` (dev only; refused in production),
`targets.{deny_cidrs, allow_cidrs, allowed_ports}`, `dial_timeout` (default
5 s, ≤ 30 s), `max_size_limit` (1000), `max_time_limit` (60 s),
`rate_per_minute` (30), `max_connections_per_tenant` (10). Validated at start
(CIDRs parse; ports 1..65535; limits in range); `Warnings()` lists
`allow_plaintext` and any `allow_cidrs` entry. `enabled: false` removes the
routes (404) and the nav entry.

## D16. Testing strategy (Constitution IV)
**Decision**:
- `ldapdir`: table + fuzz tests (filter compile/combine invariants, DN scoping,
  URL validation, target policy, GUID decoding, attribute mapping), 100 %.
- `ldapdir` exposes `Directory` (Dial → Session{StartTLS, Bind, Search,
  Close}) as an interface; `ldapdir/fake` provides an in-memory directory
  (entries, base DN, aliases, referrals, size/time-limit behaviour, error
  injection) so `directory` service tests run offline.
- The real client is tested against an `httptest`-style local TLS LDAP only
  through integration tests: **testcontainers OpenLDAP** (see D17) with
  ldaps + StartTLS + seeded people (incl. an alias pointing outside the base,
  a referral, a 1 MiB attribute, duplicate emails, entries without mail) —
  `//go:build integration` in `tests/integration/ldap_import_test.go`.
- Negative security tests: filter injection/base escape, plaintext refusal in
  production, skip-verify impossible, untrusted CA, SSRF (loopback,
  169.254.169.254, a hostname resolving to 127.0.0.1, disallowed port),
  password never in any response/log/audit/error (sentinel scan), imported user
  vs unknown at sign-in/recovery/invite-accept (same body, status, timing
  class, no lockout, no outbox), deactivate→reactivate refused, cross-tenant
  connection/user ids → 404 + `cross_tenant_refused`, escalation at activation.
- Contract test: every new route in `console.yaml`; the `Connection` schema has
  no readable password field.
- Console: vitest unit tests + Playwright e2e (import page, users activate).

## D17. OpenLDAP for tests and the dev stack
**Decision**: Build a small repo-owned image from `alpine` (pinned by digest)
with the `openldap`, `openldap-back-mdb` and `openldap-overlay-*` packages
(`services/auth/tests/integration/testdata/openldap/Dockerfile` + `slapd.ldif`
+ seed `people.ldif` + a test CA/server cert generated at test start and
mounted), started by testcontainers `FromDockerfile`. Optional dev-stack
service `openldap` (compose profile `ldap`) reusing the same Dockerfile, on
the stack network, with the stack's `configs/auth.yaml` adding its IP range to
`directory.targets.allow_cidrs`.
**Rationale**: `osixia/openldap` has had no release since 2021 (stale OpenLDAP
2.4); `bitnami/openldap` moved to Bitnami's restricted/legacy catalogue in 2025
and is no longer a dependable free image — both to be re-verified at
implementation. Alpine's OpenLDAP 2.6 package is maintained and security-
patched, and a 10-line Dockerfile keeps the supply chain auditable
(Constitution VI). Active Directory specifics (objectGUID binary, `(objectClass=
user)`) are covered by fake-directory unit tests; AD is not available as a
container.
**Alternatives**: testcontainers-go `modules/openldap` (defaults to the Bitnami
image — rejected for the reason above unless re-verified); Samba AD DC
container (heavy, flaky; optional manual check only).

## D18. Console
**Decision**: In `services/auth/console` (auth's own Vue console, `@freya/ui`
kit, drawers not dialogs):
- `views/admin/Directories.vue` — list of connections (name, URL, TLS mode,
  last test outcome/time) + `DirectoryDrawer.vue` (create/edit, kind presets
  filling the attribute mapping, CA PEM textarea, password field write-only
  with "stored — leave blank to keep", "Test connection" showing the failing
  step, delete confirm noting imported users stay).
- `views/admin/DirectoryImport.vue` — connection picker, filter input, optional
  base + scope, Search → preview table (name, email, status chip new /
  existing / imported / invalid, truncation notice), multi-select, Import →
  result summary (created/updated/skipped with reasons/failed).
- `views/admin/Users.vue` — `imported` status chip + filter option (add to
  `api/vocab.ts` `userStatuses`), directory origin column/tooltip, row actions
  for `imported`: "Activate — send invitation" (opens `ActivateDrawer.vue`
  with role and group pickers — reusing InviteDialog's pickers) and "Remove";
  multi-select + bulk "Activate"; per-user failures listed in a toast/summary.
- Routes `/admin/directories`, `/admin/directories/import` (`meta.roles:
  ['owner','admin']` plus the `directory:manage` ability for custom roles);
  zod schemas `schemas/directory.ts`.

## Supply-chain note (Constitution VI)
New direct dependency for `services/auth` only: `github.com/go-ldap/ldap/v3`
(MIT, actively maintained, widely deployed); transitive
`github.com/go-asn1-ber/asn1-ber` (MIT, same maintainers) and
`github.com/Azure/go-ntlmssp` (MIT; pulled in for NTLM bind, which we do not
use — accepted as a transitive). None is in any repository `go.sum` today.
Purpose: LDAPv3 protocol + RFC 4515 filter compiler + RFC 4514 DN parser.
Alternatives rejected in D2. Pin by checksum, `GOFLAGS=-mod=readonly`,
`govulncheck` in `make vuln`, review on every bump. Test image: repo-owned
Alpine-based OpenLDAP Dockerfile pinned by digest (D17). No new cryptography:
TLS from stdlib `crypto/tls`, sealing via the existing `internal/crypto`.

## STRIDE summary
- **Spoofing**: a spoofed/MITM directory feeding false users or harvesting the
  bind password → TLS mandatory with verification against system roots or the
  pinned CA, no skip-verify, StartTLS before bind, no plaintext outside dev (D3);
  a browser forging import entries → import re-fetches by unique id from the
  directory (D8); console callers → session cookie + CSRF + `directory:manage`
  / `users:manage` gates (D12).
- **Tampering**: filter injection widening the search → compile, canonicalise,
  AND-combine with the base filter, base DN scoping, alias deref off, per-entry
  DN re-check (D6); ciphertext swapping between tenants → envelope associated
  data (D4).
- **Repudiation**: every connection change, test, search, import, activation
  and removal audited append-only with actor, tenant, subject and outcome (D14).
- **Information disclosure**: bind password → sealed, write-only, closed error
  vocabulary, sentinel redaction tests (D4, D9); account enumeration through
  imported users → sign-in/recovery/accept treat them as unknown, no lockout
  oracle, deactivate/reactivate refused (D10); cross-tenant connections/users →
  RLS + 404 + `cross_tenant_refused` (data-model); directory PII in audit →
  ids and counts only (D14).
- **Denial of service**: huge/slow searches → server + client size/time
  limits, attribute allow-list, BER packet cap, per-request import cap, rate
  limit on test/search (D5, D7); connection sprawl → per-tenant cap (D15).
- **Elevation of privilege**: SSRF / internal port scanning via the URL →
  dial-time IP policy, port allow-list, coarse errors, rate limit (D5);
  activation granting roles beyond the actor → shared escalation check, also
  applied to plain invitations (D11); imported user becoming active without an
  invitation → only `invite.Accept` can move `invited → active`, reactivate
  refused for `imported` (D10).
