---

description: "Task list for 019 Module Roles and Module-Scoped Permissions"
---

# Tasks: Module Roles and Module-Scoped Permissions

**Input**: Design documents from `specs/019-module-roles/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: MANDATORY (Constitution IV). Tests precede implementation in every
phase and must fail first. Negative security tests and fuzz tests are
listed explicitly.

**Paths**: prefixed per repository — `auth/` = go-tangra-auth,
`portal/` = go-tangra-portal-v4, `<module>/` = go-tangra-<module>-v4
(warden, notification, lcm, deployer, paperless, asset, inventory, ipam,
ticket, dns).

**Release tasks** (tags, PR merges, stack pins) require explicit user
confirmation before they are executed.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Add `internal/permref` to `SECURITY_PKGS` in `auth/scripts/coverage-gate.sh` and to `COVERPKG` in `auth/Makefile`; add `FuzzQualifiedRef` and `FuzzModuleRoleSlug` to the `make fuzz` list
- [X] T002 Proto changes per contracts/grpc.md in `auth/sdk/api/proto/auth/v1/auth.proto` (`CheckRequest.module`, `PermissionRef.module`, `RegisterPermissionsRequest.module/module_display_name/roles/declares_roles`, `ModuleRoleDef`, response `skipped_grants/role_errors/roles_upserted/roles_retired`, `SkippedGrant`, `RoleError`); `buf lint`, `buf breaking` against `sdk/v4.0.0` (additive only), regenerate `auth.pb.go`/`auth_grpc.pb.go`

---

## Phase 2: Foundational (blocking)

### Tests first

- [X] T003 [P] Grammar tests in `auth/internal/permref/permref_test.go` (100 %): parse/format qualified `module:res:act` and legacy `res:act`, rejects (empty parts, 4 parts, uppercase, `~`, `/`, over-long module/resource/action), OpenFGA object ids scoped and legacy with round-trip, `ModuleFromSPIFFE` (`spiffe://td/svc/warden` → `warden`; non-`svc/` paths, nested paths, bad names refused), module role slug `m.<module>.<slug>` build/parse, custom slug grammar rejects dots and reserved `owner|admin|member|auditor|operator`
- [X] T004 [P] Fuzz targets `FuzzQualifiedRef`, `FuzzModuleRoleSlug` and extended `FuzzFGAObjectID` (module-qualified ids never parse into another tenant; parse∘format identity) in `auth/tests/fuzz/parsers_fuzz_test.go`
- [X] T005 [P] Migration test `auth/tests/integration/upgrade_test.go`: database at 0010 with tenants, roles, grants, groups → 0011 applies; constraint names asserted before change; legacy rows `module=''`; builtin roles `origin=builtin`; CHECKs refuse a custom slug with a dot, a module role without module, `builtin ≠ (origin=builtin)`; catalogue tables readable in tenant scope, writable only with `app.system`; `tenant_modules` isolated by RLS — implemented in `auth/internal/store/modules_test.go` (`TestMigration0011Upgrade`, next to the migration helpers)
- [X] T006 [P] Store tests in `auth/internal/store/modules_test.go`: upsert/list modules, module permissions, role defs (retire/unretire), tenant_modules marker, module-scoped permissions and role_permissions (same `res:act` in two modules coexist), role origin fields round-trip
- [X] T007 [P] OpenFGA backend tests: duplicate add and missing delete succeed with the conflict options (`auth/tests/integration/authz_test.go`, OpenFGA v1.20.0); fake backend semantics unchanged for module-qualified objects (`auth/internal/authz/fga_test.go`)

### Implementation

- [X] T008 `auth/internal/permref` package: `Ref{Module, Resource, Action}`, `Parse`, `ParseLegacy`, `String`, `Object(tid)`, `ModuleFromSPIFFE`, `ModuleRoleSlug`, `ParseCustomSlug`, reserved slugs
- [X] T009 Migration `auth/internal/store/migrations/0011_module_roles.sql` per data-model.md (tables, columns, constraints, RLS policies, grants)
- [X] T010 Store: models and repos in `auth/internal/store/{models.go,repos.go,modules.go}` (module-aware `UpsertPermission`/`ListPermissions`/`ReplaceRolePermissions`/`ListRolePermissions`, catalogue CRUD, role origin); memstore fake `auth/internal/memstore/{memstore.go,modules.go}`
- [X] T011 `SDKBackend.Write` uses `OnDuplicateWrites: ignore` / `OnMissingDeletes: ignore`; writes chunked to ≤ 100 tuples (`auth/internal/authz/fga.go`)
- [X] T012 `auth/internal/authz/objects.go`/`client.go`: `PermissionRef` gains `Module`; `PermissionObject` delegates to `permref`; `ObjectTenant` accepts both object forms; tuple helpers module-aware
- [X] T013 Audit types `module_registered`, `module_role_upserted`, `module_role_retired`, `role_cloned`, `permission_migrated`, `permission_pruned` in `auth/internal/audit/audit.go` (+ vocabulary list)

**Checkpoint**: foundation tests green; `internal/permref` at 100 %; schema at 0011.

---

## Phase 3: User Story 3 — Permissions belong to one module (P1) 🎯 MVP basis

**Goal**: module-scoped registration and checks, no access lost, gateway sends the module.

**Independent Test**: a role holding only `warden:backup:manage` exports warden backups and is refused ipam backup export; after upgrade every pre-existing holder keeps access (verify reports no loss).

### Tests (auth)

- [X] T014 [P] [US3] Registration tests `auth/internal/grpcapi/authorization_test.go`: caller `svc/warden` without module → permissions under `warden`; with `module: warden` → same; **negative**: `svc/warden` with `module: ipam` → `PermissionDenied` + audit; gateway with `module: ipam` → accepted under `ipam`; gateway without module → legacy rows only, no `gateway` module created; gateway with `roles`/`declares_roles`/`builtin_grants` → `InvalidArgument`; gateway with `module: auth` → no change; non-`svc/` identity → denied; limits (201 permissions, 21 roles) → `InvalidArgument`
- [X] T015 [P] [US3] Check tests `auth/internal/grpcapi/authorization_test.go` + `auth/internal/authz/effective_test.go`: gateway with module → scoped object; gateway without module → legacy object; service without module → own module, legacy fallback only while the scoped permission is unknown; **negative**: service asking for another module → `PermissionDenied`; **cross-module denial**: role with `warden:backup:manage` → `ipam:backup:manage` denied, `warden:stats:read` holder denied `lcm:stats:read`; cache keys distinct for scoped vs legacy (`dec:` values never cross)
- [X] T016 [P] [US3] Migration (D3) tests `auth/internal/authz/modules_test.go`: first scoped registration grants `M:res:act` to every role (custom, built-in, group-assigned) holding legacy `res:act`, for every registering module; idempotent on repeat; marker set only after the tuple write (fake backend failure → marker unset, retry completes); `permission_migrated` audited; **no-loss**: effective permissions of every user (direct + groups) before ⊆ after, gains only the per-module split
- [X] T017 [P] [US3] Legacy mirror (D2) tests: while legacy `res:act` exists, built-in grants of a registration also grant the legacy object; module and custom roles never receive legacy grants; after prune no legacy writes
- [X] T018 [P] [US3] CLI tests `auth/internal/app/permissions_cli_test.go`: `verify` (snapshot/compare, per-role legacy vs scoped, exit 1 on loss, lists custom roles named `operator`/`auditor` that received module grants), `prune-legacy -dry-run` counts, `prune-legacy` refuses when verify reports a loss, removes legacy rows, mirror rows and tuples, audit `permission_pruned`
- [X] T019 [P] [US3] Integration `auth/tests/integration/module_scope_test.go`: pre-019 data → upgrade → old-style registration (no module) from `svc/warden` and `svc/ipam` → checks with module allowed exactly as before; cross-module denial against real OpenFGA; verify clean; prune; checks still allowed; tenant created mid-rollout keeps legacy checks working — implemented in `auth/tests/integration/module_roles_test.go` (`TestModuleScopeRollout`)
- [X] T020 [P] [US3] Contract tests `auth/tests/contract/authz_grpc_test.go`: new fields round-trip; old clients (fields absent) behave as before

### Implementation (auth)

- [X] T021 [US3] `auth/internal/authz/registry.go`: module-aware `Register` (catalogue upsert via `modules.go`, per-tenant rows in one transaction, tuples after commit), delegate rules (D7), legacy-only path for the gateway without module
- [X] T022 [US3] `auth/internal/authz/modules.go`: D3 migration per tenant (marker-last), legacy mirror of built-in grants (D2)
- [X] T023 [US3] `auth/internal/authz/decide.go`: module-aware catalogue lookup, scoped/legacy resolution, cache key with qualified ref, `grantingRole` module-aware
- [X] T024 [US3] `auth/internal/grpcapi/authorization.go`: caller module via `permref.ModuleFromSPIFFE`, gateway identity from `gateway.service`, module on `Check`/`BatchCheck`/`RegisterPermissions`, response fields, audit `module_registered`
- [X] T025 [US3] `auth/internal/app/gatewaymode.go` + `auth/pkg/authmanifest/manifest.go`: auth registers as module `auth` ("Authentication") through the same path; built-in grants module-scoped
- [X] T026 [US3] Escalation, assignment and group paths use qualified refs (`auth/internal/authz/{escalation.go,assign.go,groups.go,roles.go}`)
- [X] T027 [US3] `auth/cmd/authsvc/permissions.go` + `auth/internal/app/permissions_cli.go`: `permissions verify [-tenant] [-snapshot f] [-compare f]`, `permissions prune-legacy [-dry-run]`
- [X] T028 [US3] `auth/api/openapi/console.yaml` and `auth/internal/httpapi/roles.go`: qualified refs in role bodies and `/admin/permissions` (`ref`, `module`, `module_display_name`, `legacy`); legacy refs kept on update only if already held

### Tests (portal)

- [ ] T029 [P] [US3] `portal/internal/authz/decide_test.go`: `Allowed` sends `module` in `PermissionRef`; cache key includes module (same `res:act` in two modules cached separately); `validPerm` accepts only bare refs from manifests; audit unchanged
- [ ] T030 [P] [US3] `portal/internal/authz/abilities_test.go` + `portal/internal/httpapi/shell_api_test.go`: `Held`/`Abilities`/`/me/modules` keyed by `module:res:act`; a user holding `warden:stats:read` does not see ticket's Dashboard nav (`stats:read`)
- [ ] T031 [P] [US3] `portal/internal/app/permissions_test.go`: `SyncPermissions` sends `module` and `module_display_name` per registration, never roles or grants
- [ ] T032 [P] [US3] `portal/internal/authz/bind/http_test.go`: HTTP and gRPC routes decide `rt.Module`/`m.Module` scoped permissions; **negative**: permission of another module refused

### Implementation (portal)

- [ ] T033 [US3] Bump auth SDK to `sdk/v4.1.0` in `portal/go.mod` (after T076)
- [ ] T034 [US3] `portal/internal/authz/decide.go`: `Check` takes `(module, res:act)` pairs; `PermissionRef.Module`; key `gwdec:<t>:<u>:<module>:<res:act>@<ver>`
- [ ] T035 [US3] `portal/internal/authz/abilities.go`, `portal/internal/httpapi/shell_api.go`: qualify nav/ability `requires` with the registration module
- [ ] T036 [US3] `portal/internal/authz/bind/http.go`: pass the route module through (no manifest change)
- [ ] T037 [US3] `portal/internal/app/permissions.go`: module + display name in `SyncPermissions`

**Checkpoint**: cross-module bleed closed for upgraded components; no access lost (T016, T019).

---

## Phase 4: User Story 1 — Assign a module's ready-made role (P1)

**Goal**: modules declare locked roles that exist in every tenant; clone; retirement.

**Independent Test**: with warden upgraded, a new tenant shows Warden administrator/editor/viewer; assigning Warden viewer grants exactly `warden:secrets:read`.

### Tests (auth)

- [X] T038 [P] [US1] Role instantiation tests `auth/internal/authz/modules_test.go`: definitions create `m.<module>.<slug>` roles (origin module, locked) with exactly their permissions in every requested tenant; update diff on changed permissions keeps assignments; `declares_roles` without a slug retires it everywhere (assignments and grants kept), re-declaring un-retires; gateway registrations never touch roles; `module_role_upserted`/`module_role_retired` audited; **negative**: role naming a permission not in the request (another module's or unregistered) → `role_errors foreign_permission`, other roles applied; invalid slug/name, > 200 permissions, duplicate slug → rejected individually
- [X] T039 [P] [US1] Tenant creation tests `auth/internal/tenant/tenant_test.go`: new tenant receives every non-retired module permission and role from the catalogue plus built-ins (incl. `auditor`) without any re-registration
- [X] T040 [P] [US1] Lock and clone tests `auth/internal/authz/roles_test.go` + `auth/internal/httpapi/roles_test.go`: update/remove of a module role → `403 managed_role`; clone → custom role with the source permissions (legacy grants not copied), `role_cloned` audited; **negative (escalation)**: clone by an actor lacking a permission → `403 self_escalation`; clone of owner refused; slug taken → `409`; cloned role is editable
- [X] T041 [P] [US1] Assignment tests `auth/internal/authz/assign_test.go`, `groups_test.go`, `auth/internal/invite/*_test.go`, activation tests: **negative (escalation)**: assigning a module role with a permission the actor lacks → `self_escalation` (users, groups, invitations, activation); retired role → `409 role_retired` unless already held; accepting an invitation drops retired roles with audit detail
- [X] T042 [P] [US1] `authsvc modules retire <name>` test: module roles retired, permissions hidden from `/admin/permissions`, grants kept
- [X] T043 [P] [US1] SDK helper tests `auth/sdk/pkg/authclient/registration_test.go`: `Validate` (limits, grammar, own-permission rule, grant refs), `Request` sets `declares_roles`, `Register` logs skipped grants and role errors against a fake server
- [X] T044 [P] [US1] Integration `auth/tests/integration/module_roles_test.go`: register warden-like roles → assign viewer → check `warden:secrets:read` allowed, `warden:secrets:write` denied; new tenant has the roles; retirement keeps the existing assignee's access — `TestModuleRolesEndToEnd` in the same file

### Implementation (auth)

- [X] T045 [US1] `auth/internal/authz/modules.go`: catalogue role defs, per-tenant instantiation/update/retirement with mirror diff and tuples, SR-002 validation
- [X] T046 [US1] `auth/internal/authz/roles.go`: `ErrManagedRole`, `ErrRoleRetired`, `Clone` via `Create`, origin/module fields in `RoleView`/`RoleName`, reserved slugs
- [X] T047 [US1] Retired-role refusal in `auth/internal/authz/{assign.go,groups.go}`, `auth/internal/invite`, activation (`auth/internal/user`); invitation acceptance drops retired roles
- [X] T048 [US1] `auth/internal/tenant/tenant.go` + `auth/internal/app/app.go`: `OnCreated` instantiates the catalogue (module permissions + roles) and auth's own permissions
- [X] T049 [US1] `auth/internal/httpapi/roles.go`: `POST /admin/roles/{id}/clone`, `managed_role`/`role_retired` errors, role fields per contracts/http.md; OpenAPI update
- [X] T050 [US1] `auth/cmd/authsvc/modules.go`: `modules retire <name>` (operator CLI, audit `module_role_retired`)
- [X] T051 [US1] `auth/sdk/pkg/authclient/registration.go`: `ModuleRole`, `Permission`, `Registration.Validate/Request/Register`
- [X] T052 [P] [US1] Console tests `auth/console/tests/unit/roles.spec.ts`: roles list origin badges, retired badge, clone dialog (slug suggestion, errors), edit/remove hidden for module roles, module role opens read-only with Clone
- [X] T053 [US1] Console `auth/console/src/views/admin/{Roles.vue,RoleGroupPickers.vue,InviteDialog.vue}`, `auth/console/src/api/vocab.ts` (`managed_role`, `role_retired`, new audit types)

### Modules (declare roles, use the SDK helper; after T076)

Each module task: bump auth SDK to `sdk/v4.1.0`; declare `Roles []authclient.ModuleRole` in the manifest per research D9 (display "<DisplayName> <role>"); replace the hand-written request (`internal/app/permissions.go` or manifest `SeedRequest`) with `authclient.Registration{Module, DisplayName, Permissions, Roles, BuiltinGrants: Grants}.Register`; keep built-in `Grants`; manifest test (every role permission declared, slugs valid, ≤ 20 roles, `Validate()` passes, module = SPIFFE service name in the stack config) written first.

- [ ] T054 [P] [US1] `warden/pkg/wardenmanifest/manifest.go`, `warden/internal/app/permissions.go` (+ tests): administrator, editor, viewer
- [ ] T055 [P] [US1] `notification/pkg/notificationmanifest/manifest.go`, `notification/internal/app/permissions.go` (+ tests): administrator (without `events:publish`, user decision, research D9), sender, viewer
- [ ] T056 [P] [US1] `lcm/pkg/lcmmanifest/manifest.go`, `lcm/internal/app/permissions.go` (+ tests): administrator, operator, viewer
- [ ] T057 [P] [US1] `deployer/pkg/deployermanifest/manifest.go`, `deployer/internal/app/permissions.go` (+ tests): administrator, operator, viewer
- [ ] T058 [P] [US1] `paperless/pkg/paperlessmanifest/manifest.go`, `paperless/internal/app/permissions.go` (+ tests): administrator, editor, viewer
- [ ] T059 [P] [US1] `asset/pkg/assetmanifest/manifest.go` (`SeedRequest` → helper, + tests): administrator, editor, viewer
- [ ] T060 [P] [US1] `inventory/pkg/inventorymanifest/manifest.go` (+ tests): administrator, editor, viewer
- [ ] T061 [P] [US1] `ipam/pkg/ipammanifest/manifest.go` (+ tests): administrator (incl. power:control, kvm:access), operator, viewer
- [ ] T062 [P] [US1] `ticket/pkg/ticketmanifest/manifest.go` (+ tests): convert `Roles` map (`"ticket admin|agent|viewer"`) to administrator, agent, viewer; `Grants` reference the new roles
- [ ] T063 [P] [US1] `dns/pkg/dnsmanifest/manifest.go` (+ tests): convert `Roles` map (`"dns admin|viewer"`) to administrator (`TenantPermissions()`), viewer; `Grants` reference the new roles

**Checkpoint**: US1 demonstrable (quickstart steps 4, 6, 8, 9).

---

## Phase 5: User Story 2 — Permissions grouped by module in the role editor (P1)

**Goal**: editor sections per module, then resource; per-module select-all limited to grantable permissions.

**Independent Test**: New role shows one section per registered module with its display name; "backup: manage" appears under each module separately.

### Tests

- [X] T064 [P] [US2] HTTP tests `auth/internal/httpapi/roles_test.go`: `/admin/permissions` returns module, display name, sorted by display name ("Authentication" for auth), `grantable` true for owners and only held permissions for a delegated role manager, retired modules omitted, legacy rows flagged
- [X] T065 [P] [US2] Console tests `auth/console/tests/unit/role-editor.spec.ts`: sections by module display name then resource; same action under two modules independently selectable; "Select all in module" selects only grantable ones; non-grantable disabled; "Before modules" section only when the role holds legacy grants; submit sends qualified refs

### Implementation

- [X] T066 [US2] `auth/internal/httpapi/roles.go` + `auth/internal/authz/registry.go`: catalogue listing with display names and `grantable` (batched `AllowedMany`)
- [X] T067 [US2] `auth/console/src/views/admin/RoleEditor.vue`, `auth/console/src/schemas/role.ts`: module/resource grouping, per-module select all/clear, legacy section, read-only module roles with Clone
- [X] T068 [US2] Playwright scenario in `auth/console/tests/e2e/roles.spec.ts` (or `TestRolesPlaywright` like 018): new role with permissions from two modules; module role clone — `TestRolesPlaywright` (`auth/tests/integration/roles_playwright_test.go`, E2E_PLAYWRIGHT=1)

**Checkpoint**: US2 demonstrable (quickstart step 5).

---

## Phase 6: User Story 4 — Built-in role grants are never silently lost (P2)

**Goal**: `auditor` in every tenant; grants only to built-in roles; missing roles reported.

**Independent Test**: a module granting `stats:read` to `auditor` results in an auditor role holding `<module>:stats:read` in every tenant; a grant to `operator` in customer tenants is reported in `skipped_grants`.

### Tests

- [X] T069 [P] [US4] `auth/internal/authz/roles_test.go`: `GrantBuiltin` only targets `builtin` roles; **negative**: custom role named `operator` (pre-existing) receives no module grants; creating custom `auditor`/`operator` refused
- [X] T070 [P] [US4] `auth/internal/grpcapi/authorization_test.go`: missing built-in role → `skipped_grants{role, tenants, sample_tenant_ids ≤ 5, reason role_missing}` and a warn log; no silent drop
- [X] T071 [P] [US4] `auth/internal/app/builtin_test.go` + `auth/tests/integration/tenant_test.go`: `EnsureBuiltinRoles` adds `auditor` (row + tenant tuple) to every existing tenant including the platform tenant, idempotent; adopts an existing custom `auditor` role (grants and assignments kept, audit `adopted`); new tenants get `auditor`; platform tenant keeps `operator`

### Implementation

- [X] T072 [US4] `auth/internal/tenant/tenant.go` (`BuiltinRoles` + auditor), `auth/internal/app/app.go` (platform set + auditor), `auth/internal/app/builtin.go` (`EnsureBuiltinRoles` at start)
- [X] T073 [US4] `auth/internal/authz/roles.go` + `auth/internal/grpcapi/authorization.go`: built-in-only grants, skipped grant aggregation in the response and log

**Checkpoint**: US4 demonstrable; SC-005.

---

## Phase 7: Polish & Release

- [X] T074 [P] Docs: `auth/docs/operations.md` (module roles, catalogue, rollout order, `verify`/`prune-legacy`/`modules retire`), `auth/docs/security-model.md` (module identity, delegate rule, STRIDE), OpenAPI final check; module READMEs mention their roles — auth docs done; module READMEs belong to T054–T063
- [ ] T075 Gates (auth): coverage (100 % set incl. `internal/permref`, ≥ 80 % total), `govulncheck`, `go vet`, `buf lint`/`breaking`, fuzz smoke, console lint + unit + build; portal and each module: tests, vet, govulncheck — auth part done 2026-09-26 (coverage gate, govulncheck auth+sdk, vet, golangci-lint, buf lint/breaking, fuzz smoke, console lint/vitest/build, integration suite); portal and module gates pending
- [ ] T076 Release **auth** (next minor, e.g. v4.4.0) and **auth SDK `sdk/v4.1.0`** — PR, CI, tags (confirm with the user); deploy to freya-stack
- [ ] T077 Release **portal gateway** (next minor) after T033–T037 — PR, CI, tag (confirm with the user); deploy right after auth
- [ ] T078 Release **modules** one by one after T054–T063 (warden, notification, lcm, deployer, paperless, asset, inventory, ipam, ticket, dns) — PR, CI, tag each (confirm with the user); watch registration logs for `skipped_grants`/`role_errors`
- [ ] T079 Run quickstart.md in freya-stack; record results in `auth/specs/019-module-roles/quickstart-results.md`
- [ ] T080 Cut-over: `authsvc permissions verify` clean on every tenant → `authsvc permissions prune-legacy -dry-run` → `prune-legacy` (confirm with the user); re-run verify and quickstart steps 3 and 10
- [ ] T081 go-tangra-docker: pin the released auth, gateway and module versions (confirm with the user)

---

## Dependencies & Execution Order

- Setup (T001–T002) → Foundational (T003–T013) → US3 auth (T014–T028) → US1 auth (T038–T053) and US2 (T064–T068) and US4 (T069–T073) → auth release (T076) → portal (T029–T037, T077) → modules (T054–T063, T078) → cut-over (T079–T081).
- US1, US2 and US4 depend on US3's module-aware registry and decider; US2 and US4 do not depend on US1 (they can run in parallel with it).
- Module tasks and the portal bump need the published SDK (`sdk/v4.1.0`, T076).
- T080 (prune) only after the gateway and every module run the new versions and `verify` is clean.

### Parallel Opportunities

- T003–T007; T014–T020; T029–T032; T038–T044; T052 with backend US1 tasks; T054–T063 (ten repos); T064–T065; T069–T071.

## Implementation Strategy

MVP = US3 + US1 in auth (scoped permissions, preserved access, module roles
with warden as the first module). Then the editor grouping (US2) and
built-in role reporting (US4) in the same auth release. Release auth + SDK,
then the gateway, then modules one at a time (each first registration
migrates its grants), then the verified cut-over.
