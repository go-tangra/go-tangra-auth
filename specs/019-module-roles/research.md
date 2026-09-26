# Research: Module Roles and Module-Scoped Permissions (019)

Evidence from go-tangra-auth `main` (v4.3.0 + 018), go-tangra-portal-v4
`main` (gateway, v4.2.1), and the module repos go-tangra-{warden,
notification, lcm, deployer, paperless, asset, inventory, ipam, ticket,
dns}-v4 (`pkg/<m>manifest/manifest.go`). Auth SDK: latest tag `sdk/v4.0.0`.

## Current state

### Permission identity

- A permission is `(tenant, resource, action)`: table `permissions`
  PK `(tenant_id, resource, action)` and `role_permissions`
  PK `(role_id, resource, action)` (`internal/store/migrations/0001_schema.sql:62-76`).
- OpenFGA object `permission:<tid>/<res>~<act>` (`internal/authz/objects.go:56-60`),
  model `permission.granted: [role#assignee]` (`internal/authz/model.fga`).
- Reference grammar `resource:action`, each `[a-z0-9][a-z0-9_.-]{0,63}`
  (`ParsePermissionRef`, `objects.go:31-44`); the SQL CHECKs are narrower
  (`resource ^[a-z][a-z0-9_-]{0,63}$`, `action ^[a-z][a-z0-9_-]{0,31}$`).
- `store.UpsertPermission` overwrites `registered_by` on conflict
  (`internal/store/repos.go:387-392`), so the last registrant wins.

### Shared references across modules (verified in the manifests)

| Reference | Registered by |
|---|---|
| `backup:manage` | warden, notification, lcm, deployer, paperless, asset, inventory, ipam, ticket, dns (10) |
| `stats:read` | warden, notification, lcm, deployer, paperless, asset, inventory, ticket (8) |
| `permissions:manage` | warden, notification, lcm, paperless (4) |
| `jobs:read`, `jobs:manage` | lcm, deployer |
| `templates:manage` | notification, dns |
| `categories:manage` | asset, paperless |
| `locations:manage` | asset, ipam |
| `groups:manage` | ipam, auth |

Consequences today:

- ipam grants `backup:manage` to `operator` (`ipammanifest/manifest.go:64-68`)
  → a platform operator can export/import backups of **every** module.
- deployer, paperless, asset and inventory grant `stats:read` to `member`
  → every member reads warden, lcm, notification and ticket statistics and
  audit trails, which those modules reserve for owner/admin/auditor.
- ipam's `groups:manage` (IP groups) and auth's `groups:manage` (user
  groups) are one permission: granting one grants the other.

### Registration

- `auth.v1.Authorization/RegisterPermissions{permissions, tenant_ids,
  builtin_grants}` (`sdk/api/proto/auth/v1/auth.proto:153-164`), served by
  `internal/grpcapi/authorization.go:75-126`. The registrant is the caller's
  SPIFFE id string (`serviceCtx`); empty `tenant_ids` = all active tenants
  (`app.activeTenantIDs`); grants may only name permissions of the same
  request; role names allowed: owner, admin, member, auditor, operator.
- Registration is not transactional: `Registry.Register` upserts rows one by
  one, then writes the OpenFGA tenant tuples of new permissions;
  `Roles.GrantBuiltin` writes grant tuples, then the `role_permissions` mirror.
- `GrantBuiltin` returns nil when the tenant has no role with that slug
  (`internal/authz/roles.go:296-303`) — the grant is silently lost — and it
  matches **any** role with the slug, built-in or not.
- Built-in roles: customer tenants `owner, admin, member`
  (`internal/tenant/tenant.go:46`); platform tenant `owner, admin, operator`
  (`internal/app/app.go:474`). `auditor` exists in no tenant; `operator`
  exists only in the platform tenant. Custom role creation reserves only
  `owner, admin, member` (`roles.go:138`).
- Every module registers with builtin grants to all five slugs
  (warden/notification/lcm/deployer/paperless `internal/app/permissions.go`;
  asset/inventory/ipam/ticket/dns `SeedRequest()` in the manifest package),
  at start and every 5 minutes.
- The gateway re-registers every registered module's permissions under its
  own identity every 5 minutes (portal `internal/app/permissions.go:13-52`),
  without grants, overwriting `registered_by`.
- auth registers its own permissions in-process as `"auth"`
  (`internal/app/gatewaymode.go:16-31`) at start and on tenant creation
  (`Tenants.OnCreated`, `app.go:266-270`). **Module permissions reach a new
  tenant only at the next module or gateway re-registration** (≤ 5 min).
- dns and ticket already define `Roles` maps (`"dns admin"`, `"dns viewer"`,
  `"ticket admin|agent|viewer"` — names with spaces) used only to compute
  their builtin grants; nothing sends them to auth.

### Checks

- Gateway HTTP and gRPC routes: `Decider.Allowed(module, tenant, user,
  "res:act")` (portal `internal/authz/bind/http.go:48,95`) → `Check` →
  auth `BatchCheck{PermissionRef{resource, action}}`. The module is known
  but used only for the audit event. Cache `gwdec:<t>:<u>:<res:act>@<ver>`
  (2 s, `internal/authz/decide.go:149-151`); auth caches
  `dec:<t>:<u>:<res:act>@<ver>` (`internal/authz/decide.go`).
- `/me/modules` and `/me/abilities` use `Decider.Held` keyed by bare
  `res:act` over all visible modules (portal
  `internal/httpapi/shell_api.go:76-158`, `internal/authz/abilities.go:101-158`).
- In-process checks: dns and ticket (`internal/app/permissions.go`
  `AuthPerms.Has`), notification and lcm (`internal/app/perms.go`) call
  `Authorization/Check{resource, action}` directly.
- Unknown `res:act` in a tenant → `unknown_permission` (deny).

### Roles, grants and escalation

- `roles(id, tenant_id, slug, display_name, builtin)`, slug CHECK
  `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (no dots), `UNIQUE(tenant_id, slug)`.
- OpenFGA role object `role:<tid>/<slug>`; assignments by user
  (`role_bindings`) or group (`group_roles`, 0005); JWT `roles` carries slugs.
- Escalation: `Escalation.MayGrant` (owners exempt, system actor exempt) is
  used by role create/update, `Assigner.MayAssign` (users, invitations,
  imported-user activation) and `Groups.SetRoles`.
- OpenFGA has no tuple-read API in the backend interface
  (`internal/authz/client.go:20-29`); role grants are mirrored in
  `role_permissions` and tuples are written only for mirror differences.
  There is no re-sync job.
- Console role editor groups by resource only
  (`console/src/views/admin/RoleEditor.vue:34-39`); refs validated by
  `/^[a-z0-9_-]+:[a-z0-9_-]+$/` (`console/src/schemas/role.ts:8`).

## Decisions

### D1 — Module-scoped permission identity
**Decision**: a permission is `(tenant, module, resource, action)`.
OpenFGA object `permission:<tid>/<module>~<res>~<act>`; qualified reference
`module:resource:action` in APIs, audit and UI. The module is the service
name of the caller's SPIFFE id (`spiffe://<td>/svc/<name>`), `auth` for
auth's own permissions. Module grammar `^[a-z][a-z0-9-]{0,31}$`. Longest
object id: 11 + 36 + 1 + 32 + 1 + 64 + 1 + 64 = 210 bytes (OpenFGA limit 256).
**Rationale**: the only way to make "backup:manage in warden" and "in ipam"
independent (FR-001/002) without renaming every module permission; the
module is already known at every check site (gateway route, caller identity).
**Alternatives**: prefix resources (`warden-backup:manage`) — rejected:
every module, route declaration, CASL rule and console would change, and
nothing would stop a module from registering another module's prefix;
many-to-many modules ↔ shared permission objects — rejected: keeps the
bleed, it only labels it.

### D2 — Compatibility (legacy rows)
**Decision**: existing rows get `module = ''` (legacy). Checks:
- with a module → the module-scoped object only;
- without a module from a **module service** → module := caller's service
  name (D8); if that scoped permission is unknown in the tenant but the
  legacy one is known (module not yet re-registered), the legacy object;
- without a module from the **gateway** (old gateway) → the legacy object
  (today's behaviour).
Registrations without `module` are attributed to the caller's service
name; the gateway identity without `module` updates only legacy rows
(an old gateway must not create permissions of a module named `gateway`).
While legacy rows exist, builtin grants of a registration are also written
to the legacy object when a legacy permission with the same `res:act`
exists in the tenant (keeps an old gateway working in tenants created during
the window; this is exactly today's semantics and ends at prune). Module
roles and custom roles never get legacy grants. Cut-over:
`authsvc permissions prune-legacy [-dry-run]` after every module and the
gateway are upgraded; it refuses unless `verify` (D3) reports no loss, then
deletes legacy rows, mirror rows and tuples (audit `permission_pruned`
per tenant, count only).
**Rationale**: FR-015 and the rollout order (auth → gateway → modules)
without any window in which a request is denied that is allowed today.
**Alternatives**: flag day (all repos at once) — rejected: 12 releases
cannot be atomic; double checks (scoped OR legacy) permanently — rejected:
keeps the cross-module bleed.

### D3 — Access preservation at first scoped registration
**Decision**: when module M first registers scoped permissions in tenant T
(`tenant_modules.legacy_migrated_at IS NULL`), every role of T holding
legacy `res:act` that M registers is granted `M:res:act` too (system actor,
escalation not applied, audit `permission_migrated` with role, module and
count). Per tenant: one PostgreSQL transaction writes permissions, mirror
rows; OpenFGA tuples are written after commit, and `SDKBackend.Write`
sets the go-sdk v0.8.2 write options `OnDuplicateWrites: ignore` /
`OnMissingDeletes: ignore` (supported by the pinned OpenFGA v1.20.0) so a
repeated write is harmless. The marker `legacy_migrated_at` is committed in
a second short transaction only after the tuple write succeeded, so a failed
write makes the next registration repeat the idempotent migration. `authsvc permissions verify [-tenant id]`
compares, per tenant and role, legacy grants against scoped grants of every
module registering that `res:act`, and per principal (users directly and
through groups) the effective set before/after (mirror rows, sampled against
OpenFGA with `BatchCheck`), and prints losses and gains; exit status 1 on
any loss (SR-004).
**Note**: the design brief says "inside the registration transaction";
PostgreSQL and OpenFGA cannot share one, hence the commit-marker-last order.
**Alternatives**: one-shot SQL migration — rejected: module lists are not
known to auth before modules register; migrating on read — rejected: hidden
writes on the decision path.

### D4 — Platform catalogue
**Decision**: system-scope tables (read by every tenant scope, written only
with `app.system`): `modules(name, display_name, registered_at, updated_at,
retired_at)`, `module_permissions(module, resource, action, description,
retired_at)` and `module_role_defs(module, slug, display_name, description,
permissions text[], retired_at, updated_at)`. Registration upserts the
catalogue, then instantiates in the requested tenants (all active by
default). Tenant creation (`OnCreated`) instantiates every non-retired module
permission and role definition, so new tenants no longer wait for the
next re-registration. `roles` gains `origin (builtin|module|custom)`,
`module`, `module_slug`, `description`, `retired_at`; module role slug is
`m.<module>.<slug>` — the custom slug grammar has no dots, so the `m.` prefix
is reserved by construction; the table CHECK becomes "custom grammar, or
origin = module and the `m.` grammar".
**Correction to the brief**: `module_permissions` is added — without it
tenant creation cannot instantiate module roles (their permissions must
exist in the tenant first).
**Alternatives**: keep module roles only in memory of each module and
re-send them every 5 minutes — rejected: new tenants would lack them for up
to 5 minutes and nothing would record retirement.

### D5 — Locked module roles, clone, retirement
**Decision**: `Update`/`Remove` of a role with `origin = module` return
`ErrManagedRole` (HTTP 403 `managed_role`, message hints at cloning).
`POST /api/v1/admin/roles/{id}/clone {slug, display_name}` creates a custom
role with the source's current permissions through the normal `Create`
(escalation check, audit `role_cloned` with source id). A definition no
longer declared by its module (`declares_roles = true` and slug absent) is
retired: `retired_at` set in the catalogue and every tenant copy, grants and
assignments kept, new assignments refused (`ErrRoleRetired`, HTTP 409
`role_retired`) from users, groups, invitations and activation; accepting an
invitation drops retired roles (audit detail). A role that is declared again
is un-retired. `authsvc modules retire <name>` retires a module removed from
the platform (roles retired, permissions hidden from the editor).
**Rationale**: FR-007..009; a locked role can change under the module's
control, so administrators customise through clones.
**Alternatives**: editable module roles overwritten on upgrade — rejected by
the user (locked); delete retired roles — rejected: silently removes access.

### D6 — Built-in roles
**Decision**: `auditor` becomes a built-in role of every tenant (customer and
platform), created at tenant creation and, for existing tenants, by an
idempotent start-up reconciliation (`EnsureBuiltinRoles`: rows + role tenant
tuple; SQL cannot write OpenFGA). `operator` stays platform-only. A
customer-tenant custom role already named `auditor` is adopted as the
built-in role (keeps its grants and assignments; audit `role_updated` with
`adopted: true`). `GrantBuiltin` only targets `builtin = true` roles, and
custom role creation reserves `owner, admin, member, auditor, operator`.
Grants to a missing built-in role are returned in
`RegisterPermissionsResponse.skipped_grants` (role, tenant count, sample
tenant ids, reason) and logged by auth (warn) and by the SDK helper.
**Found gap**: today `GrantBuiltin` fills any role whose slug matches,
built-in or not, and `operator`/`auditor` are not reserved in customer
tenants: a holder of `roles:manage` can create an empty custom role
`operator`, which passes the escalation check, and modules then grant it
their operator permissions (e.g. ipam `backup:manage`, lcm
`certificates:revoke`) within 5 minutes — a privilege escalation closed here
(`verify` lists such roles; their past grants are kept for the administrator
to review).
**Alternatives**: drop grants to auditor/operator — rejected: modules target
them deliberately (FR-014).

### D7 — Gateway
**Decision**: `Decider.Allowed` sends `module` in `PermissionRef`; the cache
key becomes `gwdec:<t>:<u>:<module>:<res:act>@<ver>`; `Held`/`Abilities` are
keyed by `module:res:act` (nav and ability `requires` stay bare in manifests
and are qualified with the registration's module). `SyncPermissions` sends
`module` and `module_display_name` per manifest. auth accepts `module ≠
caller` only from the gateway identity (`spiffe://<td>/svc/<gateway.service>`,
config `gateway.service`, default `gateway`) and never with `roles`,
`declares_roles` or `builtin_grants`. For module `auth` (auth is in the
gateway registry too) a delegated registration is accepted but changes
nothing: auth's in-process registration is authoritative. Every
delegated registration is audited `module_registered` with `delegate:
gateway`. auth cannot verify the gateway's registry; the gateway is already
trusted with every HTTP decision, so this adds no new trust.
**Alternatives**: only modules register (gateway stops) — rejected: modules
not running at the moment would miss tenants; with D4 the gateway sync is
now a belt-and-braces refresh of display names and descriptions.

### D8 — In-process module checks
**Decision**: unchanged in dns, ticket, notification and lcm: when a
non-gateway service sends `Check`/`BatchCheck` without module, auth fills the
module from the caller's service name (D2 fallback). A service may also send
its own module explicitly; a module ≠ caller from a non-gateway service is
refused (`PermissionDenied`), so a module cannot ask about another module's
permissions.
**Rationale**: zero code change in four modules for checks; the identity is
authoritative.

### D9 — Module role sets
Display names `"<Module> administrator|operator|editor|sender|agent|viewer"`
(module display name from the manifest). Slugs are the last word.
Permission names verified against each manifest — all exist.

| Module (display) | Role | Permissions |
|---|---|---|
| warden (Warden) | administrator | all 10 |
| | editor | secrets:read, secrets:write, secrets:share, folders:manage, permissions:manage |
| | viewer | secrets:read |
| notification (Notifications) | administrator | all but `events:publish` (12, user decision) |
| | sender | channels:read, templates:read, notifications:send, notifications:read, messages:read, messages:manage, inbox:read |
| | viewer | channels:read, templates:read, notifications:read, messages:read, inbox:read |
| lcm (Certificates) | administrator | all 14 |
| | operator | certificates:read/issue/manage/revoke, issuers:read, jobs:read, jobs:manage, enrollment:enroll |
| | viewer | certificates:read, issuers:read, jobs:read |
| deployer (Deployer) | administrator | all 9 |
| | operator | configurations:read, targets:read, jobs:read, jobs:manage, deploy:execute |
| | viewer | configurations:read, targets:read, jobs:read, stats:read |
| paperless (Paperless) | administrator | all 9 |
| | editor | documents:read, documents:write, categories:read, search:read |
| | viewer | documents:read, categories:read, search:read |
| asset (Assets) | administrator | all 13 |
| | editor | assets:read, assets:manage, assets:assign, stats:read |
| | viewer | assets:read, stats:read |
| inventory (Inventory) | administrator | all 8 |
| | editor | inventory:read, inventory:write, snapshots:read |
| | viewer | inventory:read, snapshots:read, stats:read |
| ipam (IPAM) | administrator | all 13 incl. power:control, kvm:access (handlers still require platform-admin) |
| | operator | ipam:read, addresses:allocate, scan:run |
| | viewer | ipam:read |
| ticket (Tickets) | administrator | all 8 (replaces "ticket admin") |
| | agent | tickets:read, tickets:manage, tags:manage |
| | viewer | tickets:read |
| dns (DNS) | administrator | `TenantPermissions()` — all but config:manage (replaces "dns admin") |
| | viewer | zones:read, dashboard:read |

Module display names (manifest `DisplayName`): Warden, Notifications,
Certificates (lcm), Deployer, Paperless, Assets, Inventory, IPAM, Tickets,
DNS — e.g. "Certificates operator", "Assets viewer". Built-in grants stay
(module-scoped from now on).

**Decision (user, 2026-09-26)**: "Notifications administrator" does **not**
include `events:publish` — it is a module-to-module permission, not an
administrator capability; the notification administrator role is therefore
the 12 other permissions. The role definitions live in the module manifests,
so this only affects the notification module task (T055).

### D10 — Contract and SDK helper
**Decision**: additive proto fields in the auth SDK (contracts/grpc.md):
`module` on `PermissionRef` and `CheckRequest`; `module`,
`module_display_name`, `roles`, `declares_roles` on
`RegisterPermissionsRequest`; `skipped_grants`, `role_errors`,
`roles_upserted`, `roles_retired` on the response. Released as
**`sdk/v4.1.0`** (the latest SDK tag is `sdk/v4.0.0`; the brief's
`sdk/v4.4.0` assumed the service tag series). Helper
`authclient.Registration{Module, DisplayName, Permissions, Roles,
BuiltinGrants}` with `Request()`, `Validate()` and `Register(ctx, conn, log)`
(logs skipped grants and role errors) replaces the ten hand-written requests.
Refinement: `module` is a request field, not a `PermissionDef` field — one
registration covers one module, and a per-definition module would only add a
mixed-module case that must be refused anyway.

### D11 — Limits and validation
≤ 200 permissions and ≤ 20 roles per registration; ≤ 200 permissions per
role; role slug `^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`; display name 1–120
printable characters; description ≤ 256; a role may only name permissions of
the same request (SR-002) — a role naming anything else is rejected
individually (`role_errors`), the rest of the registration applies.

### D12 — Console
Role editor groups by module display name (sorted, "Authentication" for
`auth`), then resource; per-module "select all" selects only permissions
with `grantable: true` (computed by auth for the actor); legacy permissions
(until prune) appear in a "Before modules" group, read-only unless already
held. Roles list: origin badge (platform / module name / custom), retired
badge with explanation, clone action on every non-built-in role; module
roles open read-only with a "Clone" button.

### D13 — Audit vocabulary
New: `module_registered` (module, delegate, counts), `module_role_upserted`,
`module_role_retired`, `role_cloned`, `permission_migrated`,
`permission_pruned`. Permission details use qualified refs.

### D14 — Coverage
New pure package `internal/permref` (qualified/legacy ref parsing and
formatting, OpenFGA object ids, module-from-SPIFFE, slug grammars) joins the
100 % set; `internal/authz` stays under the 80 % total gate (the OpenFGA SDK
backend is exercised only by integration tests).

## Threat model (STRIDE)

| Threat | Vector | Mitigation |
|---|---|---|
| Spoofing | A module registers permissions or roles as another module | Module from the verified SPIFFE id; `module ≠ caller` only from the gateway identity, which cannot send roles or grants (D7, SR-001) |
| Spoofing | Old gateway registrations attributed to a module named `gateway` | Gateway without module updates legacy rows only (D2) |
| Tampering | Module role containing another module's permissions | Roles may only name permissions of the same request (D11, SR-002) |
| Tampering | Administrator edits a module role | Locked (`managed_role`), clone instead (D5) |
| Tampering | Custom role named like a built-in receives module grants | `GrantBuiltin` only targets built-in roles; slugs reserved (D6) |
| Repudiation | Who registered, changed or retired roles; who cloned | `module_registered`, `module_role_upserted/retired`, `role_cloned`, `permission_migrated/pruned` (D13) |
| Information disclosure | Cross-module bleed (`stats:read`, `backup:manage`) | Module-scoped objects (D1); checks with module (D7/D8) |
| Denial of service | Oversized registrations | Limits (D11); per-tenant work bounded |
| Denial of service | Access lost during migration | D3 migration, D2 fallbacks, `verify` before `prune-legacy` |
| Elevation of privilege | Assigning or cloning a module role with permissions the actor lacks | Same `MayAssign`/`MayGrant` as any role (SR-003) |
| Elevation of privilege | Retired role keeps granting | Retired roles keep existing assignments only (spec); visible; new assignments refused |
| Elevation of privilege | Compromised module declares a broad role | Only its own permissions; administrators still decide assignments; audit |

## Implementation notes (auth, 2026-09-26)

Where the implementation refines or deviates from the design above, the
safer option was taken:

1. **D3 transaction.** PostgreSQL and OpenFGA cannot share a transaction, and
   the service's stores open one transaction per call. Every grant change is
   therefore written to OpenFGA first (idempotent writes, D3 options, chunks
   of ≤ 100 tuples), then to the mirror; the migration marker is written
   last. A failure between the steps leaves the mirror behind OpenFGA and
   the next registration converges (`TestMigrationMarkerLast`).
2. **Gateway checks with a module fall back to legacy** while the module has
   not registered the permission in the tenant (the contract table listed
   the scoped object only). Without it, a gateway upgraded before a module
   (rollout step 2 before 3) would deny `unknown_permission` for every
   permission of not-yet-upgraded modules. The fallback returns exactly the
   pre-019 answer and ends as soon as the module registers.
3. **Checks refuse smuggled modules**: `resource`/`action` of a check must be
   short names (a resource like `warden:backup` is `InvalidArgument`).
4. **Role error vocabulary** adds `no_permissions` (a declared role without
   permissions). A rejected role keeps its previous definition: it is not
   retired by a `declares_roles` registration that fails to re-declare it
   validly.
5. **Built-in grants are not stored in the catalogue**: a new tenant gets the
   module permissions and roles at creation, the module built-in grants at
   the module's next registration (≤ 5 min), as before 019. auth's own
   built-in grants are applied at creation.
6. **Platform-wide audit events** (`module_registered`,
   `module_role_upserted`, `module_role_retired`, `module_mismatch`
   refusals) are recorded in the platform tenant; `permission_migrated`,
   `permission_pruned` and `role_cloned` in the tenant concerned.
7. **`verify`** exits 1 on a loss; `pending` (legacy grants no module
   registered yet) and `drift` (mirror grants OpenFGA does not confirm,
   sampled for 50 users per tenant) do not change the exit status but block
   `prune-legacy`, which removes nothing unless every tenant is clean.
8. **Retired roles are refused for operators and the system actor too**
   (invitation escalation check), not only for tenant administrators.
9. **Start-up reconciliation** (built-in roles incl. `auditor`, auth's own
   registration) now also runs in standalone (non-gateway) mode, where auth
   permissions used to be seeded only by `authsvc bootstrap`.
10. **Custom role slugs** follow the database grammar (1–63 characters, no
    dots) and refuse the five built-in slugs; the migration test lives in
    `internal/store/modules_test.go` (which owns the migration helpers)
    rather than `tests/integration/upgrade_test.go`.
