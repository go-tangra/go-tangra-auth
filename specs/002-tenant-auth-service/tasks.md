---

description: "Task list for Multi-Tenant Authentication & Authorization Service"
---

# Tasks: Multi-Tenant Authentication & Authorization Service

**Input**: Design documents from `/specs/002-tenant-auth-service/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/, quickstart.md

**Tests**: Tests are MANDATORY (Constitution Principle IV, NON-NEGOTIABLE). Every user story lists its test tasks before its implementation tasks, and tests MUST be written and confirmed failing before implementation. Every story here touches authentication, parsing, crypto or secrets, so each includes negative security tests; every parser (tokens, codes, slugs, OpenAPI bodies, FGA object ids) has a fuzz target.

**Organization**: Tasks are grouped by user story. Paths are relative to the repository root. The service is its own Go module at `services/auth` (`github.com/go-freya/freya/services/auth`, `replace ../..`); the browser-facing listener `transport/edge` is a framework addition in the core module.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- Framework addition: `transport/edge/` (core module, covered by the core coverage gate)
- Service: `services/auth/{cmd,api,internal,pkg,console,deploy,tests,docs}` per plan.md
- Console: `services/auth/console/src/...` (Vue 3 + Vuetify + TypeScript), tests in `console/tests/{unit,e2e}`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Module skeleton, toolchains, dev stack, CI gates

- [X] T001 Create Go module `services/auth/go.mod` (`module github.com/go-freya/freya/services/auth`, `go 1.25.0`, `replace github.com/go-freya/freya => ../..`) and add `github.com/openfga/go-sdk@v0.8.2`, `github.com/jackc/pgx/v5@v5.11.0`, `github.com/pressly/goose/v3@v3.28.0`, `github.com/valkey-io/valkey-go@v1.0.78`, `github.com/golang-jwt/jwt/v5@v5.3.1`, `golang.org/x/crypto@v0.57.0`, `github.com/pquerna/otp@v1.5.0`; run `go mod tidy`
- [X] T002 Create package skeleton with `doc.go` per plan.md: services/auth/{cmd/authsvc,internal/{config,tenantctx,store,cache,crypto,token,session,password,mfa,invite,tenant,user,authz,oauth,audit,email,httpapi,grpcapi},pkg/authclient,tests/{contract,integration,fuzz},docs}
- [X] T003 [P] Copy contracts into the service: `contracts/auth.v1.proto` → services/auth/api/proto/auth/v1/auth.proto, `contracts/console-api.openapi.yaml` → services/auth/api/openapi/console.yaml, `contracts/authorization-model.fga` → services/auth/internal/authz/model.fga; add services/auth/buf.yaml and services/auth/buf.gen.yaml (protoc-gen-go, protoc-gen-go-grpc) and generate
- [X] T004 [P] Create services/auth/Makefile with targets `lint`, `vuln`, `test`, `cover` (gate: ≥80 % overall, 100 % for internal/{token,session,password,mfa,tenantctx}), `fuzz`, `generate`, `console-build`, `redaction-scan`, `e2e`, `compose-up/down` reusing scripts from the repository root
- [X] T005 [P] Create services/auth/deploy/compose.yaml (timescaledb `timescale/timescaledb:latest-pg16` with two databases `auth` and `openfga`, valkey `valkey/valkey:8` with TLS + ACL user, openfga `openfga/openfga:v1.20.0` with postgres datastore + preshared key + TLS, mailpit) and services/auth/deploy/dev.yaml (service config for the stack)
- [X] T006 [P] Scaffold the console: services/auth/console/package.json (vue 3.5, vuetify 4.2, vue-router 5, pinia 4, vite 8, typescript 7 strict, vitest 5, @playwright/test 1.63, openapi-typescript), vite.config.ts (dev proxy to https://localhost:8443), tsconfig.json, eslint config, src/main.ts with Vuetify plugin, src/App.vue shell
- [X] T007 [P] Add CI job for the service in .github/workflows/ci.yml: Go gates (`make -C services/auth lint vuln test cover`), console (`npm ci && npm run lint && npm run test:unit && npm run build`, `npm audit --audit-level=high`), and an `integration` job with Docker running testcontainers + Playwright e2e against `deploy/compose.yaml`
- [X] T008 [P] Write services/auth/docs/dependencies.md justifying every direct dependency (purpose, alternatives, maintenance) from research.md §11
- [X] T009 [P] Add `services/auth/.gitignore` (console/node_modules, console/dist, .artifacts, coverage) and root `.gitignore` entries for `services/*/console/node_modules`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Framework edge listener, service config, tenant context + RLS, crypto, storage, cache, OpenFGA bootstrap, API skeletons, wiring, test harness

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Tests for Foundational (write first, confirm failing)

- [X] T010 [P] Unit tests for `transport/edge`: TLS 1.3 only, no plaintext constructor (extend tests/contract/api_surface_test.go reflection walk to `transport/edge`), self-signed cert only when env ≠ production with `insecure_mode_enabled` audit event, cert hot reload in transport/edge/server_test.go
- [X] T011 [P] Unit tests for edge security headers (HSTS, CSP default, nosniff, Referrer-Policy, Permissions-Policy, Cache-Control no-store on /api) and per-app CSP nonce injection in transport/edge/headers_test.go
- [X] T012 [P] Unit tests for edge CSRF matrix: missing cookie, missing header, mismatch, bad Origin, `Sec-Fetch-Site: cross-site`, safe methods exempt, all refused with `{"reason":"csrf"}` in transport/edge/csrf_test.go
- [X] T013 [P] Unit tests for edge rate limiter: per-IP token bucket, per-route override, `X-Forwarded-For` honoured only from trusted proxies, 429 `rate_limited` + `limit_exceeded` audit event in transport/edge/ratelimit_test.go
- [X] T014 [P] Unit tests for service `config.Load/Validate`: edge, db (sslmode ≥ verify-full unless env ≠ production), valkey TLS required, openfga URL + preshared key from secrets provider, KEK source required, email transport TLS required, all defaults in services/auth/internal/config/config_test.go
- [X] T015 [P] Unit tests for `tenantctx`: context carries verified tenant + actor; `Require(ctx, tenantID)` refuses mismatches and emits `cross_tenant_refused`; operator path needs an active grant; `WithTx` issues `SET LOCAL app.tenant_id` in services/auth/internal/tenantctx/tenantctx_test.go
- [X] T016 [P] Unit tests for `crypto`: argon2id hash/verify with versioned params + rehash-needed detection, envelope encrypt/decrypt (AES-256-GCM, DEK wrapped by KEK), constant-time compare, timing-padding helper in services/auth/internal/crypto/crypto_test.go
- [X] T017 [P] Integration tests (`//go:build integration`, testcontainers TimescaleDB) for migrations: all tables/hypertables/policies exist; RLS blocks a row from another tenant even with a direct query; retention/compression jobs registered in services/auth/internal/store/migrate_test.go
- [X] T018 [P] Unit tests for `cache` (fake Valkey interface): session set/get/TTL, revocation marks, counters with windows, decision cache TTL 2 s, pub/sub fan-out in services/auth/internal/cache/cache_test.go
- [X] T019 [P] Unit tests for the application audit writer: closed vocabulary enforced, secrets in `details` redacted, correlation/trace ids populated, batch insert to `auth_audit_events` via fake inserter in services/auth/internal/audit/audit_test.go
- [X] T020 [P] Unit tests for `email`: outbox enqueue/retry/backoff, SMTP TLS required (plaintext refused unless env ≠ production), logsink in dev in services/auth/internal/email/email_test.go
- [X] T021 [P] Unit tests for `authz` FGA adapter (fake OpenFGA server or SDK mock): store/model bootstrap idempotent, object ids always tenant-prefixed, cross-tenant object refused before any call, Check/Write mapping in services/auth/internal/authz/fga_test.go
- [X] T022 [P] Fuzz targets: `FuzzSlug`, `FuzzPermissionRef`, `FuzzFGAObjectID`, `FuzzOpenAPIBody` (sign-in/invite/policy bodies) in services/auth/tests/fuzz/parsers_fuzz_test.go
- [X] T023 [P] Unit tests for `httpapi` skeleton: OpenAPI request validation rejects unknown fields/oversize/malformed, error encoder emits `{"reason"}` only, 5xx → `internal`, session middleware attaches actor/tenant from cookie in services/auth/internal/httpapi/server_test.go
- [X] T024 [P] Contract test: OpenAPI document (api/openapi/console.yaml) parses, every implemented route is declared and vice versa in services/auth/tests/contract/openapi_test.go

### Implementation for Foundational

- [X] T025 Implement `transport/edge.NewServer` (server-auth TLS 1.3 listener, PEM hot reload, dev self-signed only when env ≠ production, chain recover → correlation → tracing → instrument → rate limit → headers → CSRF → body limit) in transport/edge/server.go, transport/edge/headers.go, transport/edge/csrf.go, transport/edge/ratelimit.go
- [X] T026 Add `transport/edge` to the core coverage gate and contract reflection walk; document in docs/security-model.md and CHANGELOG.md
- [X] T027 [P] Implement service config (extends `config.Config` with `Edge`, `DB`, `Valkey`, `OpenFGA`, `Email`, `KEK`, `Issuer`) with `Load`, `Validate`, `Warnings` in services/auth/internal/config/config.go
- [X] T028 [P] Implement `tenantctx` (Actor{UserID, TenantID, Kind, Roles, SessionID}, `FromContext`, `Require`, `WithTx` setting `app.tenant_id`/`app.operator_grant`) in services/auth/internal/tenantctx/tenantctx.go
- [X] T029 [P] Implement `crypto` (argon2id, envelope encryption with KEK from file/env secrets provider, constant-time helpers, `PadTo(d)` for enumeration-safe responses) in services/auth/internal/crypto/{password.go,envelope.go,timing.go}
- [X] T030 Write goose migrations from data-model.md (tenants, users, recovery_codes, roles, role_bindings, permissions, role_permissions, sessions, signing_keys, revocations hypertable, invitations, recovery_requests, client_applications, operator_grants, auth_audit_events hypertable, signin_attempts hypertable, outbox; RLS policies; app role without BYPASSRLS) in services/auth/internal/store/migrations/0001_schema.sql … 0004_rls.sql
- [X] T031 Implement `store` (pgx pool, `Migrate` with advisory lock, per-aggregate repositories with tenant-scoped queries) in services/auth/internal/store/{store.go,migrate.go,tenants.go,users.go,roles.go,sessions.go,keys.go,invitations.go,recovery.go,clients.go,grants.go,audit.go,outbox.go}
- [X] T032 [P] Implement `cache` (valkey-go with TLS/ACL; sessions, revocation marks, counters, lockouts, decision cache, tenant version, pub/sub `auth:revoked`) behind a `KV` interface with an in-memory fake in services/auth/internal/cache/{cache.go,valkey.go,memory.go}
- [X] T033 [P] Implement application audit writer (closed vocabulary from data-model.md, batched hypertable inserts, redaction via Freya handler) in services/auth/internal/audit/audit.go
- [X] T034 [P] Implement `email` (Sender interface, outbox worker, smtp with TLS, logsink) in services/auth/internal/email/{email.go,outbox.go,smtp.go,logsink.go}
- [X] T035 Implement `authz` FGA adapter (client with TLS + preshared key, store/model bootstrap from model.fga, tenant-prefixed object builders, Check/BatchCheck/Write wrappers, decision cache, tenant version bump) in services/auth/internal/authz/{fga.go,objects.go,cache.go}
- [X] T036 Implement `httpapi` skeleton (router on `transport/edge`, OpenAPI validation middleware, session-cookie middleware, error encoder, CSP nonce for the console, static console serving from `go:embed`) in services/auth/internal/httpapi/{server.go,middleware.go,errors.go,console.go}
- [X] T037 [P] Implement `grpcapi` skeleton registering `auth.v1` services on the Freya gRPC server with a policy file allowing platform services in services/auth/internal/grpcapi/server.go and services/auth/deploy/policy.yaml
- [X] T038 Implement `cmd/authsvc` (config → `freya.New` → stores/cache/FGA/email → httpapi on edge + grpcapi → `Run`; subcommand `bootstrap --operator-email` creating the platform tenant, operator invitation, initial signing key) in services/auth/cmd/authsvc/main.go
- [X] T039 [P] Implement the integration test harness: testcontainers for TimescaleDB, Valkey (TLS), OpenFGA, mailpit; fixture starting the service in-process with dev identities; helpers for cookies/CSRF/tokens in services/auth/tests/integration/harness_test.go
- [X] T040 [P] Console foundation: router with role guards, Pinia session store, API client from OpenAPI types adding `X-CSRF-Token`, layout (app bar, navigation by role), error/outage screen, i18n scaffold in services/auth/console/src/{router/index.ts,stores/session.ts,api/client.ts,layouts/Default.vue,views/Outage.vue}

**Checkpoint**: Foundation ready — `make -C services/auth test` green, service boots against the compose stack with an empty tenant list

---

## Phase 3: User Story 1 - Sign In and Obtain Proof of Identity (Priority: P1) 🎯 MVP

**Goal**: Tenant + email + password (+ TOTP when enrolled) sign-in through the console; short-lived EdDSA JWTs verifiable offline by platform services via published keys and a revocation feed; sessions expire and sign-out is global.

**Independent Test**: quickstart.md §3–§5 — a tenant user signs in, mints a token, a demo downstream service verifies it offline; wrong password, locked account and expired token are refused as expected.

### Tests for User Story 1 (MANDATORY) ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T041 [P] [US1] Unit tests for `password.Verify`/policy: correct/incorrect, rehash on parameter upgrade, min length, timing padding applied in services/auth/internal/password/password_test.go
- [X] T042 [P] [US1] Unit tests for `session`: create with tenant lifetime/idle timeout, cookie value hashed, touch extends idle, expiry, revoke (all reasons) writes revocation marks + log + pub/sub, list mine in services/auth/internal/session/session_test.go
- [X] T043 [P] [US1] Unit tests for `token`: EdDSA only (`alg` confusion rejected), claims per contracts/token.md, `exp−iat ≤ 900`, `kid` in key ring, key ring rotation states active→retiring→retired, JWKS output, envelope-encrypted private keys never exported in services/auth/internal/token/token_test.go
- [X] T044 [P] [US1] Fuzz targets `FuzzTokenParse` and `FuzzJWKS` in services/auth/tests/fuzz/token_fuzz_test.go
- [X] T045 [P] [US1] Unit tests for `pkg/authclient`: offline verify, key refresh on unknown `kid` (rate-capped), skew ±60 s, revocation feed application (session/user/tenant kinds with `ts ≥ iat`), fail closed when the feed is stale > 60 min in services/auth/pkg/authclient/client_test.go
- [X] T046 [P] [US1] Contract test for `auth.v1.Keys/List` and `Sessions/RevokedSince|Watch|Introspect` shapes against api/proto in services/auth/tests/contract/grpc_test.go
- [X] T047 [US1] Integration test `TestSigninMatrix`: unknown tenant, unknown email, wrong password, suspended tenant → identical 401 `invalid_credentials`; correct → cookie set; per-account/per-IP rate limits → 429; lockout after threshold → 423; one `signin_failed`/`lockout` audit row per case in services/auth/tests/integration/signin_test.go
- [X] T048 [US1] Integration test `TestEnumerationTiming`: response-time spread < 10 % across existing vs non-existing accounts over 200 samples (SC-006) in services/auth/tests/integration/timing_test.go
- [X] T049 [US1] Integration test `TestTokenLifecycle`: mint, verify offline with `pkg/authclient`, expiry refused, sign-out revokes within 10 s at the verifier, session idle/absolute expiry, `/.well-known/jwks.json` publishes active+retiring+retired keys in services/auth/tests/integration/token_test.go
- [X] T050 [US1] Integration test `TestKeyRotation`: three rotations under 200 calls/s with 0 verification errors; retired key remains published until last token expiry (SC-007) in services/auth/tests/integration/rotation_test.go
- [X] T051 [US1] Integration test `TestOAuthCodeFlow`: `/authorize` with PKCE S256 + registered redirect URI → sign-in → code → `/api/v1/oauth/token`; wrong verifier, reused code, unregistered redirect, missing state all refused in services/auth/tests/integration/oauth_test.go
- [X] T052 [P] [US1] Console unit tests (Vitest): sign-in form validation, tenant resolution, generic error rendering (never distinguishes reasons), MFA step routing in services/auth/console/tests/unit/signin.spec.ts

### Implementation for User Story 1

- [X] T053 [P] [US1] Implement `password` (policy from tenant, verify with rehash, timing pad) in services/auth/internal/password/password.go
- [X] T054 [P] [US1] Implement `token` (key ring with generation/rotation/retirement scheduler, envelope-encrypted storage, issue/verify, JWKS, revocation feed reader) in services/auth/internal/token/{keys.go,jwt.go,jwks.go,rotation.go}
- [X] T055 [US1] Implement `session` (create/touch/expire/revoke, cookie handling, revocation fan-out to Valkey + `revocations` hypertable + pub/sub) in services/auth/internal/session/session.go
- [X] T056 [US1] Implement `user` sign-in service (tenant resolve, status checks incl. suspended tenant/deactivated/locked, rate limit + lockout counters, `signin_attempts` rows, MFA challenge hand-off) in services/auth/internal/user/signin.go
- [X] T057 [US1] Implement HTTP handlers: `GET /api/v1/tenants/resolve`, `POST /api/v1/signin`, `POST /api/v1/signin/mfa` (challenge verification wired in US4), `POST /api/v1/signout`, `GET /api/v1/session`, `POST /api/v1/session/token`, `GET /api/v1/sessions`, `POST /api/v1/sessions/{id}/revoke`, `GET /.well-known/jwks.json` in services/auth/internal/httpapi/{signin.go,session.go,jwks.go}
- [X] T058 [US1] Implement gRPC `Keys.List`, `Sessions.RevokedSince`, `Sessions.Watch`, `Sessions.Introspect` (audited) in services/auth/internal/grpcapi/{keys.go,sessions.go}
- [X] T059 [P] [US1] Implement `pkg/authclient` (Verifier: JWKS/Keys refresh, offline verify, revocation feed poller/stream, fail-closed staleness, gRPC interceptor + HTTP middleware helpers exposing the end-user identity to handlers) in services/auth/pkg/authclient/{client.go,verify.go,revocations.go,middleware.go}
- [X] T060 [US1] Implement `oauth` (client registry lookup, `/authorize` rendering the console with pending request, code issue in Valkey, PKCE S256 verification, `POST /api/v1/oauth/token`) in services/auth/internal/oauth/{authorize.go,token.go,pkce.go} and services/auth/internal/httpapi/oauth.go
- [X] T061 [P] [US1] Console views: tenant + sign-in form, MFA code step, home with identity summary, session list with revoke, outage handling in services/auth/console/src/views/{SignIn.vue,MfaChallenge.vue,Home.vue,Sessions.vue}
- [X] T062 [P] [US1] Example downstream service using `pkg/authclient` over the Freya channel (`demo.v1.Demo/WhoAmI`) in services/auth/examples/downstream/main.go and services/auth/deploy/downstream.yaml
- [X] T063 [US1] Wire US1 handlers, key rotation scheduler and revocation feed into `cmd/authsvc`; document sign-in flow in services/auth/docs/security-model.md

**Checkpoint**: MVP — quickstart §2–§5 pass (with the operator/tenant created via `bootstrap` + a seed script until US5)

---

## Phase 4: User Story 2 - Tenant Administrator Manages Users and Access (Priority: P1)

**Goal**: Invitations, role assignment/revocation, deactivation, force sign-out and a filterable audit trail — strictly within the administrator's tenant.

**Independent Test**: quickstart.md §6 — admin flows reflected in next sign-in/decision and audit; every cross-tenant attempt refused, audited, and also blocked by RLS.

### Tests for User Story 2 (MANDATORY) ⚠️

- [X] T064 [P] [US2] Unit tests for `invite`: token hashing, expiry (72 h), single use, resend, identical 202 for existing/non-existing emails, accept sets password + activates + assigns roles in services/auth/internal/invite/invite_test.go
- [X] T065 [P] [US2] Unit tests for `user` admin operations: deactivate revokes sessions and denies decisions, reactivate, force sign-out, last-owner invariant, cross-tenant id → not found + `cross_tenant_refused` in services/auth/internal/user/admin_test.go
- [X] T066 [P] [US2] Unit tests for role assignment through the FGA adapter: assign/revoke writes `role#assignee` tuples + mirror rows in one transaction, tenant version bump, roles appear in the next token in services/auth/internal/authz/assign_test.go
- [X] T067 [P] [US2] Unit tests for audit query: filters by user/event_type/time, cursor pagination, tenant scoping in services/auth/internal/audit/query_test.go
- [X] T068 [US2] Integration test `TestAdminFlows`: invite → mailpit → accept → sign in; assign role → token carries it; revoke; deactivate → sessions dead within 10 s and sign-in refused; reactivate; force sign-out; each step audited exactly once in services/auth/tests/integration/admin_test.go
- [X] T069 [US2] Integration test `TestCrossTenantMatrix` (SC-002): admin of B against A's users/roles/policy/audit/sessions by guessed ids, tokens from tenant A used against B, admin without role → 403/404 + `cross_tenant_refused`; direct SQL with B's `app.tenant_id` cannot read A's rows (RLS) in services/auth/tests/integration/cross_tenant_test.go
- [X] T070 [US2] Integration test `TestRevocationPropagation` (SC-003): force sign-out, deactivation and tenant suspension observed by the downstream verifier within 10 s in services/auth/tests/integration/revocation_test.go
- [X] T071 [P] [US2] Console unit tests: users table filters/actions, invite dialog validation, role picker, audit filters in services/auth/console/tests/unit/admin.spec.ts

### Implementation for User Story 2

- [X] T072 [P] [US2] Implement `invite` (create, resend, accept, expiry sweeper) in services/auth/internal/invite/invite.go
- [X] T073 [P] [US2] Implement `user` admin operations (list/search, deactivate/reactivate with session revocation, force sign-out, last-owner guard) in services/auth/internal/user/admin.go
- [X] T074 [US2] Implement role assignment (`AssignRoles(user, roles)` with self-escalation guard from US3 stub: actor must hold every permission being granted; FGA tuple writes + mirror rows) in services/auth/internal/authz/assign.go
- [X] T075 [US2] Implement audit query service in services/auth/internal/audit/query.go
- [X] T076 [US2] Implement HTTP handlers `GET /api/v1/admin/users`, `POST /api/v1/admin/invitations`, `POST /api/v1/admin/invitations/{id}/resend`, `POST /api/v1/invitations/accept`, `PUT /api/v1/admin/users/{id}/roles`, `POST /api/v1/admin/users/{id}/deactivate|reactivate|sessions/revoke`, `GET /api/v1/admin/audit` in services/auth/internal/httpapi/{admin_users.go,invitations.go,audit.go}
- [X] T077 [P] [US2] Console views: Users (table, search, status chips, actions), Invite dialog, Accept-invitation page, User detail with roles editor, Audit trail with filters in services/auth/console/src/views/admin/{Users.vue,UserDetail.vue,InviteDialog.vue,Audit.vue} and services/auth/console/src/views/AcceptInvitation.vue
- [X] T078 [US2] Wire US2 handlers/workers into `cmd/authsvc`; add admin route guards in services/auth/console/src/router/index.ts

**Checkpoint**: both P1 stories usable together; quickstart §6 passes

---

## Phase 5: User Story 3 - Fine-Grained Authorization Decisions (Priority: P2)

**Goal**: Built-in + custom roles as permission sets; services register permissions and ask Check/BatchCheck; changes propagate within 5 s; no self-escalation.

**Independent Test**: quickstart.md §7 — custom `auditor` role allow/deny with reasons; deactivated user denied; role change visible ≤ 5 s; self-escalation refused; p95 < 20 ms at 1,000 concurrency.

### Tests for User Story 3 (MANDATORY) ⚠️

- [X] T079 [P] [US3] Unit tests for the permission registry: `resource:action` validation, idempotent registration per tenant, registrant SPIFFE ID recorded, listing in services/auth/internal/authz/registry_test.go
- [X] T080 [P] [US3] Unit tests for roles CRUD: built-ins immutable, custom role create/update/remove with FGA `permission#granted` tuples + mirrors, remove unassigns everyone, tenant version bump in services/auth/internal/authz/roles_test.go
- [X] T081 [P] [US3] Unit tests for decisions: allow with `role:<slug>` reason, `no_permission`, `user_inactive`, `tenant_suspended`, `unknown_permission`, cache hit/miss + invalidation on version bump, cross-tenant request refused before FGA in services/auth/internal/authz/decide_test.go
- [X] T082 [P] [US3] Unit tests for the self-escalation guard: actor may only grant permissions they hold; owner-only permission refused for admins in services/auth/internal/authz/escalation_test.go
- [X] T083 [P] [US3] Contract test for `auth.v1.Authorization/Check|BatchCheck|RegisterPermissions` shapes and reason vocabulary in services/auth/tests/contract/authz_grpc_test.go
- [X] T084 [US3] Integration test `TestAuthzDecisions` + `TestSelfEscalation` + `TestPropagation` (role change visible ≤ 5 s) against real OpenFGA in services/auth/tests/integration/authz_test.go
- [X] T085 [US3] Benchmark `BenchmarkCheck` (1,000 concurrent, p95 < 20 ms, SC-005) with gate script in services/auth/tests/integration/authz_bench_test.go and services/auth/scripts/authz-gate.sh
- [X] T086 [P] [US3] Console unit tests: role editor permission matrix, built-in lock, escalation error rendering in services/auth/console/tests/unit/roles.spec.ts

### Implementation for User Story 3

- [X] T087 [P] [US3] Implement permission registry in services/auth/internal/authz/registry.go
- [X] T088 [US3] Implement roles CRUD with FGA writes and mirrors in services/auth/internal/authz/roles.go
- [X] T089 [US3] Implement decisions (`Decide`, `BatchDecide` with status checks, tenant guard, cache) and the self-escalation guard in services/auth/internal/authz/{decide.go,escalation.go}
- [X] T090 [US3] Implement gRPC `Authorization.Check|BatchCheck|RegisterPermissions` in services/auth/internal/grpcapi/authorization.go
- [X] T091 [US3] Implement HTTP handlers `GET/POST /api/v1/admin/roles`, `PUT /api/v1/admin/roles/{id}`, `POST /api/v1/admin/roles/{id}/remove`, `GET /api/v1/admin/permissions` in services/auth/internal/httpapi/roles.go
- [X] T092 [P] [US3] Console views: Roles list, Role editor with permission matrix grouped by resource in services/auth/console/src/views/admin/{Roles.vue,RoleEditor.vue}
- [X] T093 [US3] Extend the downstream example to call `RegisterPermissions` at start and `Check` per request in services/auth/examples/downstream/main.go

**Checkpoint**: quickstart §7 passes

---

## Phase 6: User Story 4 - Self-Service Account Security (Priority: P2)

**Goal**: Password change (ends other sessions), TOTP enrol/confirm/disable, recovery codes, password recovery by single-use link, own-session management; tenant-required MFA enforced at sign-in.

**Independent Test**: quickstart.md §8.

### Tests for User Story 4 (MANDATORY) ⚠️

- [X] T094 [P] [US4] Unit tests for `mfa`: enrol produces otpauth URI + encrypted seed, confirm requires valid code, ±1 step window, replay of same counter refused, recovery codes hashed + single use, disable refused when tenant requires MFA in services/auth/internal/mfa/mfa_test.go
- [X] T095 [P] [US4] Fuzz targets `FuzzTOTPCode`, `FuzzRecoveryCode`, `FuzzRecoveryToken` in services/auth/tests/fuzz/codes_fuzz_test.go
- [X] T096 [P] [US4] Unit tests for password change (current password required, policy, ends other sessions only) and recovery (202 regardless, 30-min single-use token, enumeration-safe timing) in services/auth/internal/password/change_test.go and services/auth/internal/password/recovery_test.go
- [X] T097 [US4] Integration test `TestMFA` (enrol → next sign-in requires code → recovery code once → disable refused under policy), `TestPasswordChange`, `TestRecovery` (mailpit link, reuse refused, expiry), `TestSessionsSelf` (revoke one of two) in services/auth/tests/integration/selfservice_test.go
- [X] T098 [P] [US4] Console unit tests: account security page, QR/otpauth rendering, recovery-code display once, session revoke in services/auth/console/tests/unit/account.spec.ts

### Implementation for User Story 4

- [X] T099 [P] [US4] Implement `mfa` (enrol/confirm/verify/disable, recovery codes, challenge store in Valkey for the sign-in second step) in services/auth/internal/mfa/mfa.go
- [X] T100 [P] [US4] Implement password change and recovery flows (outbox email, token hashing) in services/auth/internal/password/{change.go,recovery.go}
- [X] T101 [US4] Implement HTTP handlers `POST /api/v1/me/password`, `/me/mfa/enroll|confirm|disable|recovery-codes`, `POST /api/v1/recovery`, `POST /api/v1/recovery/complete`; complete `POST /api/v1/signin/mfa`; enforce tenant `mfa_required` (enrol-before-console) in services/auth/internal/httpapi/{account.go,recovery.go} and services/auth/internal/user/signin.go
- [X] T102 [P] [US4] Console views: Account security (password, MFA enrolment wizard with QR, recovery codes), Forgot/Reset password pages, MFA-required enrolment gate in services/auth/console/src/views/{Account.vue,ForgotPassword.vue,ResetPassword.vue,MfaEnrol.vue}
- [X] T103 [US4] Wire US4 handlers into `cmd/authsvc` and router guards for the MFA-required gate in services/auth/console/src/router/index.ts

**Checkpoint**: quickstart §8 passes

---

## Phase 7: User Story 5 - Platform Operator Manages Tenants (Priority: P3)

**Goal**: Operators (platform tenant, MFA mandatory) create/suspend/reactivate tenants and obtain time-limited, audited grants for in-tenant actions; suspension revokes everything.

**Independent Test**: quickstart.md §2–§3 and §9 suspension case.

### Tests for User Story 5 (MANDATORY) ⚠️

- [X] T104 [P] [US5] Unit tests for `tenant`: slug validation, policy validation/defaults, create seeds built-in roles + owner invitation + FGA tuples, suspend revokes all sessions + marks `rev:tenant`, reactivate, platform tenant forces `mfa_required` in services/auth/internal/tenant/tenant_test.go
- [X] T105 [P] [US5] Unit tests for operator grants: creation requires reason + ≤ 4 h, in-tenant action without grant refused, expiry, every use audited (`operator_grant_used`) in services/auth/internal/tenant/grants_test.go
- [X] T106 [US5] Integration test `TestTenantLifecycle`: create → owner accepts → invites user; suspend → both sessions dead within 10 s, sign-in → 401 `tenant_suspended`; reactivate → sign-in ok; tenant admin calling operator endpoints → 403 in services/auth/tests/integration/tenant_test.go
- [X] T107 [P] [US5] Console unit tests: tenant list/create form, suspend confirmation, grant dialog in services/auth/console/tests/unit/operator.spec.ts

### Implementation for User Story 5

- [X] T108 [P] [US5] Implement `tenant` (create with seeding, suspend/reactivate with revocation fan-out, policy get/update) and operator grants in services/auth/internal/tenant/{tenant.go,policy.go,grants.go}
- [X] T109 [US5] Implement HTTP handlers `GET/POST /api/v1/operator/tenants`, `POST /api/v1/operator/tenants/{id}/suspend|reactivate`, `POST /api/v1/operator/grants`, `GET/PUT /api/v1/admin/policy`, `GET/POST /api/v1/admin/clients` in services/auth/internal/httpapi/{operator.go,policy.go,clients.go}
- [X] T110 [P] [US5] Console views: Operator tenants list/create, tenant detail with suspend/reactivate and grant dialog, Admin policy editor, Client applications in services/auth/console/src/views/operator/{Tenants.vue,TenantDetail.vue} and services/auth/console/src/views/admin/{Policy.vue,Clients.vue}
- [X] T111 [US5] Replace the temporary seed script with the real `bootstrap` flow (platform tenant, operator invitation, MFA mandatory) in services/auth/cmd/authsvc/bootstrap.go

**Checkpoint**: all five stories independently testable; quickstart §2–§9 pass

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T112 [P] Playwright e2e suite with axe accessibility checks for sign-in, users, roles, audit, account, operator screens (SC-001 timings, SC-009) in services/auth/console/tests/e2e/*.spec.ts and services/auth/console/playwright.config.ts
- [X] T113 [P] Redaction scan: run the integration suite with capture, scan logs, `auth_audit_events.details`, outbox payloads and error bodies for password hashes, TOTP seeds, cookies, tokens, keys in services/auth/tests/integration/redaction_scan_test.go and services/auth/scripts/redaction-scan.sh
- [X] T114 [P] Negative security sweep beyond the stories: oversized bodies/headers at the edge, rate-limit bursts, TLS 1.2 and plaintext at the edge, CSP/headers on every console route, `X-Forwarded-For` spoofing in services/auth/tests/integration/hardening_test.go
- [X] T115 [P] Documentation: services/auth/README.md (overview, run, move-to-own-repo procedure), services/auth/docs/security-model.md (STRIDE from research.md §12, token/session/revocation contract), services/auth/docs/operations.md (rotation, KEK, OpenFGA bootstrap, backups, RLS role)
- [X] T116 [P] Add root README.md section and CHANGELOG.md entries for `transport/edge` and `services/auth`
- [X] T117 Security hardening and constitution compliance review of the service (all seven principles) recorded in specs/002-tenant-auth-service/checklists/constitution-review.md
- [X] T118 Verify coverage thresholds (core gate incl. `transport/edge`; service ≥ 80 % overall, 100 % for internal/{token,session,password,mfa,tenantctx}) via `make cover` and `make -C services/auth cover`; fix gaps
- [X] T119 Run `gosec`, `staticcheck`, `govulncheck` (core allow-list only), `go mod verify` for both modules and `npm audit` for the console; update services/auth/docs/dependencies.md
- [X] T120 Run quickstart.md §1–§11 end-to-end on a clean checkout and record results in specs/002-tenant-auth-service/quickstart-results.md
- [X] T121 Code cleanup and refactoring pass (no behaviour change; tests stay green) across services/auth/internal and transport/edge

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories; `transport/edge` (T010–T013, T025–T026) is in the core module and can proceed in parallel with the service foundation
- **User Story 1 (P1)**: Depends on Foundational — MVP
- **User Story 2 (P1)**: Depends on US1 (sessions/tokens) and on the role-assignment stub in T074 (US3 completes the guard)
- **User Story 3 (P2)**: Depends on Foundational (FGA adapter) and US1 (actor context); independent of US2/US4
- **User Story 4 (P2)**: Depends on US1 (sign-in second step, sessions); independent of US2/US3
- **User Story 5 (P3)**: Depends on US1 and US2 (invitations); replaces the temporary seed script
- **Polish**: After all desired stories

### User Story Dependencies

- **US1** → foundation only
- **US2** → US1 (+ escalation guard finalised in US3; a permissive stub is acceptable until then, flagged in T074)
- **US3** → US1
- **US4** → US1
- **US5** → US1, US2

### Within Each User Story

- Tests MUST be written and FAIL before implementation (Constitution Principle IV)
- Domain packages before handlers; handlers before console views; wiring last
- Unit → contract → integration order when running

### Parallel Opportunities

- Setup: T003–T009 in parallel after T001–T002
- Foundational tests T010–T024 all parallel; implementations T027–T029, T032–T034, T037, T039–T040 parallel; T025/T026 (framework) parallel with the service; T030→T031→T035/T036→T038 sequential
- US1 tests T041–T046, T052 parallel; T053–T054, T059, T061–T062 parallel with T055–T058
- After US1: US3 and US4 can be worked concurrently by different developers; US2 needs T074's stub only
- Polish T112–T116 parallel

---

## Parallel Example: User Story 1

```bash
# Launch all US1 tests together:
Task: "Unit tests for password in services/auth/internal/password/password_test.go"
Task: "Unit tests for session in services/auth/internal/session/session_test.go"
Task: "Unit tests for token in services/auth/internal/token/token_test.go"
Task: "Fuzz targets in services/auth/tests/fuzz/token_fuzz_test.go"
Task: "Unit tests for pkg/authclient in services/auth/pkg/authclient/client_test.go"
Task: "Contract test for Keys/Sessions gRPC in services/auth/tests/contract/grpc_test.go"
Task: "Console sign-in unit tests in services/auth/console/tests/unit/signin.spec.ts"

# Then implement in parallel where files differ:
Task: "Implement password in services/auth/internal/password/password.go"
Task: "Implement token in services/auth/internal/token/"
Task: "Implement pkg/authclient in services/auth/pkg/authclient/"
Task: "Console sign-in views in services/auth/console/src/views/"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup (T001–T009)
2. Phase 2 Foundational (T010–T040) — includes the `transport/edge` framework work
3. Phase 3 US1 (T041–T063), using `bootstrap` plus a temporary seed script for one tenant/user
4. **STOP and VALIDATE**: quickstart §3–§5 pass; a downstream service verifies tokens offline
5. Demo: console sign-in, JWT minted, downstream `WhoAmI`, sign-out revokes within 10 s

### Incremental Delivery

1. Setup + Foundational → service boots against the compose stack
2. US1 → MVP (sign-in, tokens, revocation feed, OAuth code flow)
3. US2 → invitations, roles, deactivation, audit trail (both P1 stories complete)
4. US3 + US4 in parallel → decisions engine; self-service security
5. US5 → operators and tenant lifecycle (removes the seed script)
6. Polish → e2e/axe, redaction scan, hardening sweep, docs, compliance review

### Parallel Team Strategy

1. One developer takes `transport/edge` while another builds the service foundation
2. After US1: developer A → US2, developer B → US3, developer C → US4; US5 after US2
3. Console work can be split per story once the API client (T040) and sign-in (T061) exist
