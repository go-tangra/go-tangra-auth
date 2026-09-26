# Implementation Plan: Module Roles and Module-Scoped Permissions

**Branch**: `019-module-roles` | **Date**: 2026-09-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/019-module-roles/spec.md`

## Summary

Permissions become `(tenant, module, resource, action)`, with the module
taken from the registering service's SPIFFE identity; OpenFGA objects and
references become module-qualified (`warden:backup:manage`). Existing grants
are preserved by an access-preserving migration that runs when each module
first registers scoped permissions in a tenant, backed by legacy fallbacks
during the rollout and a verified cut-over (`authsvc permissions verify`,
`prune-legacy`). auth keeps a platform catalogue of modules, their
permissions and their role definitions, and instantiates module roles
(`m.<module>.<slug>`, locked, clonable, retirable) in every tenant including
new ones. `auditor` becomes a built-in role of every tenant; built-in grants
target only built-in roles and missing roles are reported. The gateway sends
the module with every decision and registration; modules declare their roles
in their manifests and register through a shared auth SDK helper. The
console role editor groups by module, then resource.

## Technical Context

**Language/Version**: Go 1.26 (auth, portal gateway, modules), TypeScript/Vue 3 (auth console)

**Primary Dependencies**: go-tangra/v4 framework, pgx/goose, OpenFGA go-sdk
v0.8.2 (write conflict options, no new dependency), valkey,
`@go-tangra/ui`; auth SDK `sdk/v4.1.0` (new proto fields + `authclient.Registration`)

**Storage**: PostgreSQL (migration 0011: catalogue tables, module columns,
role origin), OpenFGA v1.20.0 (module-qualified objects), Valkey (decision
cache keys)

**Testing**: `go test` unit (memstore + OpenFGA fake), negative security
tests, fuzz (`FuzzQualifiedRef`, `FuzzFGAObjectID` extended), testcontainers
integration (upgrade from the pre-019 schema, verify/prune), contract tests
(proto, OpenAPI), vitest; portal and module unit tests

**Target Platform**: Linux containers (freya-stack), behind the go-tangra gateway

**Project Type**: multi-repo platform change: go-tangra-auth (service, SDK,
console), go-tangra-portal-v4 (gateway), ten module repos

**Performance Goals**: check latency unchanged (one extra string in the
cache key); registration of 200 permissions + 20 roles in 100 tenants < 30 s
(bounded batches of OpenFGA writes, ≤ 100 tuples per write)

**Constraints**: no access lost at any point of the rollout (SC-001);
additive proto only; forward-only migration; coverage gate — 100 % for
`internal/token`, `session`, `password`, `mfa`, `tenantctx`, `ldapdir`,
`webauthn` and the new `internal/permref`; ≥ 80 % total

**Scale/Scope**: 11 modules (incl. auth), ~120 permissions, ~30 module roles,
tenants × (permissions + roles) rows

## Constitution Check

*GATE: re-checked after Phase 1 design — all PASS.*

- [x] **I. Secure by Default**: module roles locked; delegated registration
      limited to the gateway without roles/grants; built-in grants only to
      built-in roles; `prune-legacy` refuses without a clean `verify`.
- [x] **II. Zero Trust**: module identity from mTLS SPIFFE only; module ≠
      caller refused except the gateway; admin routes keep `roles:manage`.
- [x] **III. Boundary Validation**: proto limits (200/20/200), grammars in
      `internal/permref` and DB CHECKs, own-permission rule for roles,
      qualified ref pattern in OpenAPI and console schema.
- [x] **IV. Test-First**: each phase lists tests first; negative tests
      (foreign module registration, foreign permission in a role,
      cross-module denial, escalation via clone/assign, retired role
      assignment, custom role named `operator`, migration no-loss); fuzz for
      the ref/object grammar; `internal/permref` at 100 %.
- [x] **V. Observability**: `module_registered`, `module_role_upserted`,
      `module_role_retired`, `role_cloned`, `permission_migrated`,
      `permission_pruned`; skipped grants logged by auth and SDK.
- [x] **VI. Supply Chain**: no new dependency; SDK minor release; govulncheck.
- [x] **VII. Simplicity**: one identity rule (module = SPIFFE service name);
      one helper replaces ten hand-written registrations; one config value
      reused (`gateway.service`).
- [x] **Threat Model**: STRIDE in research.md.

## Project Structure

### Documentation (this feature)

```text
specs/019-module-roles/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/{grpc.md,http.md}
├── checklists/requirements.md
└── tasks.md
```

### Source Code

```text
go-tangra-auth (auth/)
  internal/permref/                         # NEW: qualified refs, object ids, module from SPIFFE, slug grammars
  internal/store/migrations/0011_module_roles.sql
  internal/store/{repos.go,models.go,modules.go}  # catalogue, module columns, role origin
  internal/memstore/{memstore.go,modules.go}
  internal/authz/{objects.go,client.go,fga.go,registry.go,roles.go,decide.go,assign.go,groups.go,escalation.go}
  internal/authz/modules.go                 # NEW: catalogue sync, role instantiation/retirement, migration (D3)
  internal/grpcapi/authorization.go         # module attribution, delegate rule, new response fields
  internal/tenant/tenant.go                 # auditor built-in, catalogue instantiation on create
  internal/app/{app.go,gatewaymode.go,builtin.go,permissions_cli.go}
  internal/httpapi/roles.go                 # catalogue fields, clone, managed/retired errors
  internal/invite, internal/user (activation) # retired-role refusal
  internal/audit/audit.go
  cmd/authsvc/{permissions.go,modules.go}   # verify, prune-legacy, modules retire
  pkg/authmanifest/manifest.go              # module "auth", display "Authentication"
  sdk/api/proto/auth/v1/auth.proto (+ generated), sdk/pkg/authclient/registration.go
  api/openapi/console.yaml
  console/src/views/admin/{RoleEditor,Roles,RoleGroupPickers,InviteDialog}.vue, schemas/role.ts, api/vocab.ts
  tests/{fuzz,integration,contract}/…
  docs/{operations.md,security-model.md}

go-tangra-portal-v4 (portal/)
  internal/authz/{decide.go,abilities.go}   # module in PermissionRef, cache key, Held keyed by module
  internal/authz/bind/http.go               # qualified checks for HTTP and gRPC routes
  internal/httpapi/shell_api.go             # /me/modules qualified
  internal/app/permissions.go               # module + display name in SyncPermissions

modules (<m>/ = go-tangra-<m>-v4)
  pkg/<m>manifest/manifest.go               # Roles []authclient.ModuleRole, Registration()
  internal/app/permissions.go (warden, notification, lcm, deployer, paperless) or manifest SeedRequest (asset, inventory, ipam, ticket, dns)
```

**Structure Decision**: auth owns the model, migration, catalogue, SDK
contract and console; the gateway only qualifies what it already knows
(route module); modules only declare data and call the helper. Release order:
auth + SDK → gateway → modules → cut-over.

## Rollout

1. **auth** (service vX.Y.0 next minor, e.g. 4.4.0) and **auth SDK
   `sdk/v4.1.0`**: accepts old and new registrations and checks (D2),
   instantiates catalogue, `auditor` reconciliation. Deploy.
2. **portal gateway** (next minor): module in decisions and caches,
   `SyncPermissions` with module/display name. Deploy right after auth
   (tenants created in between keep working through the D2 legacy mirror).
3. **Modules**, one by one (any order): manifest roles + SDK helper; their
   first registration migrates grants per tenant (D3).
4. **Cut-over**: `authsvc permissions verify` → clean →
   `authsvc permissions prune-legacy`. Then the legacy branches are removed
   in a later auth release (not part of this feature).

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Legacy/scoped dual state until cut-over | No-loss rollout across 12 independently released repos | Flag day across 12 repos is not atomic; permanent OR-check keeps the bleed |
| Platform catalogue tables (3) | New tenants need module permissions and roles immediately; retirement must be recorded | Re-sending from modules every 5 min leaves new tenants without roles and cannot record retirement |
| Gateway allowed to register for other modules | Modules offline at registration time still get their permissions refreshed | Module-only registration; with the catalogue it is a refresh, and the gateway is already trusted for every HTTP decision |
