# Implementation Plan: Multi-Tenant Authentication & Authorization Service

**Branch**: `002-tenant-auth-service` | **Date**: 2026-09-15 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-tenant-auth-service/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command; its definition describes the execution workflow.

## Summary

Build `services/auth`: a Freya-based service that authenticates end users of many
tenants (password + TOTP second factor), issues short-lived signed proofs of identity
(JWT, Ed25519) that platform services verify offline, answers fine-grained
authorization questions through OpenFGA, and gives tenant administrators and platform
operators a Vue 3 + Vuetify console. TimescaleDB holds all durable state (tenants,
users, roles, sessions, keys, and hypertables for the security audit trail and sign-in
attempts); Valkey holds session state, revocations, rate-limit counters and decision
caches. Platform services reach the service over the feature-001 mTLS channel; browsers
reach a new TLS-1.3 "edge" listener contributed back to the framework. The service is
its own Go module so it can move to a separate repository unchanged.

## Technical Context

**Language/Version**: Go 1.26 (toolchain go1.26.8; the OpenFGA SDK and its transitive dependencies require ≥ 1.26) for the service; TypeScript 7 for
the console (Node 22 LTS toolchain for builds only)

**Primary Dependencies**:
- `github.com/go-freya/freya` (this repo; `replace ../..` until the split) — mTLS
  transports, identity, authz-of-services, audit, observability
- `github.com/go-kratos/kratos/v3` (via Freya) — HTTP routing/errors
- `github.com/openfga/go-sdk` v0.8.2 against OpenFGA server v1.20.0 — end-user
  authorization engine (user directive)
- `github.com/jackc/pgx/v5` v5.11.0 — TimescaleDB/PostgreSQL access;
  `github.com/pressly/goose/v3` v3.28.0 — embedded SQL migrations
- `github.com/valkey-io/valkey-go` v1.0.78 — sessions, revocations, counters, caches
- `github.com/golang-jwt/jwt/v5` v5.3.1 — JWT issue/verify (EdDSA only, algorithm pinned)
- `golang.org/x/crypto` v0.57.0 — argon2id; `github.com/pquerna/otp` v1.5.0 — TOTP
- Console: Vue 3.5, Vuetify 4.2, Vite 8, TypeScript 5.9, vue-router 5, Pinia 4;
  tests with Vitest 5 and Playwright 1.63
- Test only: `testcontainers-go` (TimescaleDB, Valkey, OpenFGA), Playwright

**Storage**: TimescaleDB (PostgreSQL 16 + timescaledb): relational tables for tenants,
users, roles, role bindings, permission registry, sessions (durable metadata),
invitations, recovery requests, signing keys (encrypted), client applications;
hypertables `auth_audit_events` (FR-020) and `signin_attempts` (lockout analytics).
Row-level security policies keyed by `app.tenant_id` as defence in depth (SR-001).
OpenFGA uses the same PostgreSQL instance (separate database) as its datastore.
Valkey: `sess:<sid>` (session state + TTL), `rev:sid:<sid>` / `rev:user:<uid>` /
`rev:tenant:<tid>` (revocation marks), `rl:*` (rate limits), `lock:<uid>` (lockouts),
`dec:<tid>:<uid>:<perm>` (decision cache, 2 s), `csrf:*` is not needed (double-submit).

**Testing**: Go `testing` (unit, table-driven), fuzz targets for every parser (policy
inputs, JWT claims, TOTP/recovery codes, invitation tokens, OpenAPI request bodies),
contract tests against `contracts/`, integration tests with testcontainers
(TimescaleDB + Valkey + OpenFGA) under `//go:build integration`, negative security
matrix (cross-tenant, enumeration timing, replay after revocation, CSRF, XSS headers),
console: Vitest unit + Playwright end-to-end against the dev compose stack.
Coverage: ≥80 % overall; 100 % for `internal/{token,session,password,mfa,tenantctx}`.

**Target Platform**: Linux containers (Kubernetes); dev via docker-compose
(`services/auth/deploy/compose.yaml`: timescaledb, valkey, openfga, mailpit).

**Project Type**: Web service (Go backend + embedded SPA console) with a gRPC
service-to-service API and a small Go client library for downstream services.

**Performance Goals**: sign-in (password + TOTP) p95 < 400 ms excluding email;
authorization decision p95 < 20 ms at 1,000 concurrent requests (SC-005); JWT
verification offline in downstream services (SC-004); revocation visible everywhere
≤ 10 s (SC-003); 1,000 tenants / 100,000 users without degradation (SC-010).

**Constraints**: constitution v1.0.0 — TLS 1.3 only, no plaintext listeners, argon2id
for passwords, AEAD for secrets at rest, secrets from a provider (KEK), deny-by-default,
audit with redaction, closed error vocabularies; SR-001…SR-007 of the spec;
constant-time responses for enumeration-sensitive flows (SC-006); access tokens ≤ 15 min.

**Scale/Scope**: 5 user stories, ~35 HTTP endpoints, 6 gRPC methods, 1 OpenFGA model,
~14 tables, ~25 console screens; single region, single OpenFGA store.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Evaluate this feature against `.specify/memory/constitution.md` (v1.0.0). Mark each gate
PASS, FAIL (with Complexity Tracking entry), or N/A (with one-line reason).

- [x] **I. Secure by Default**: PASS. Cookies `Secure; HttpOnly; SameSite=Strict`;
      strict security headers (CSP without inline scripts, HSTS, frame-deny); argon2id;
      TOTP required for operators; access tokens 15 min; every listener TLS 1.3 (service
      mTLS via Freya, browser edge server-auth TLS with a public certificate — see
      Complexity Tracking #1); dev conveniences (mailpit, self-signed edge cert) require
      `env != production`.
- [x] **II. Zero Trust**: PASS for service-to-service (all platform calls use the
      Freya channel; OpenFGA and databases reached over TLS with dedicated credentials
      from the secrets provider). Browser calls are not service-to-service; end-user
      identity is established by this service and carried in signed tokens.
- [x] **III. Boundary Validation**: PASS. OpenAPI-driven request validation for the
      console/public API, protobuf for gRPC, strict parsers for tokens/codes/slugs,
      body/header/rate limits from Freya plus per-route rate limits at the edge; RLS in
      PostgreSQL re-enforces tenant scoping below the application layer.
- [x] **IV. Test-First (NON-NEGOTIABLE)**: PASS. Every story has negative security tests
      (cross-tenant matrix, enumeration timing, replay after revocation, self-escalation,
      CSRF/XSS headers) and fuzz targets for all parsers; testcontainers for real
      TimescaleDB/Valkey/OpenFGA in CI.
- [x] **V. Observability**: PASS. Freya audit stream for transport events plus the
      application audit hypertable (FR-020) written through the same redacting logger;
      correlation IDs from Freya propagate into audit rows; metrics on the admin listener.
- [x] **VI. Supply Chain**: PASS. Eight new direct Go dependencies, each justified in
      research.md §11 and `services/auth/docs/dependencies.md`; console dependencies
      pinned with a lockfile and audited in CI (`npm audit --audit-level=high`);
      OpenFGA runs as a separate, pinned container image.
- [x] **VII. Simplicity**: PASS with two justified additions (Complexity Tracking):
      OpenFGA as an external authorization engine, and the OAuth 2.1 authorization-code
      + PKCE subset for FR-023. Typed config via Freya `config` + service extension;
      no ORM, no code generation beyond protobuf/OpenAPI types.
- [x] **Threat Model**: PASS. STRIDE for browser, service, store, email and operator
      boundaries in research.md §12.

*Post-Phase 1 re-check (2026-09-15)*: all gates still PASS. Design added no dependency
beyond the list; the edge listener is specified as a framework package with the same
TLS floor; RLS policies and the tenant-context middleware cover SR-001 at two layers.

## Project Structure

### Documentation (this feature)

```text
specs/002-tenant-auth-service/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
│   ├── console-api.openapi.yaml   # Browser/public HTTP API (console + client-app flow)
│   ├── auth.v1.proto              # Service-to-service gRPC API (Freya channel)
│   ├── authorization-model.fga    # OpenFGA model (tenant-scoped RBAC)
│   ├── token.md                   # JWT claims, JWKS, revocation feed, cookie/CSRF contract
│   └── edge-listener.md           # Framework addition: transport/edge (browser-facing TLS)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
transport/edge/                    # FRAMEWORK ADDITION (go-freya core): browser-facing TLS 1.3 listener
├── server.go                      #   server-auth TLS (PEM or ACME), security headers, CSRF, rate limit
└── server_test.go

services/auth/                     # own Go module: github.com/go-freya/freya/services/auth (replace ../..)
├── go.mod
├── cmd/authsvc/main.go            # wires config → freya.App → edge listener → OpenFGA → stores → HTTP/gRPC
├── api/
│   ├── proto/auth/v1/auth.proto   # = contracts/auth.v1.proto (buf generate)
│   └── openapi/console.yaml       # = contracts/console-api.openapi.yaml
├── internal/
│   ├── config/                    # service config (extends freya config): edge, db, valkey, openfga, email, kek
│   ├── tenantctx/                 # tenant/actor context, RLS `SET LOCAL`, cross-tenant guard
│   ├── store/                     # pgx repositories per aggregate; migrations/ (goose, embedded)
│   ├── cache/                     # valkey: sessions, revocations, rate limits, lockouts, decision cache
│   ├── crypto/                    # argon2id, envelope encryption (KEK → DEK), constant-time helpers
│   ├── token/                     # JWT issue/verify, key ring + rotation, JWKS, revocation feed
│   ├── session/                   # session lifecycle, cookies, refresh, revocation fan-out
│   ├── password/                  # policy, hashing, change, recovery flow
│   ├── mfa/                       # TOTP enrolment/verification, recovery codes
│   ├── invite/                    # invitations
│   ├── tenant/                    # tenants, security policy, operator access grants
│   ├── user/                      # users, status transitions, last-owner rule
│   ├── authz/                     # OpenFGA adapter, role/permission registry, decision cache, self-escalation guard
│   ├── oauth/                     # authorization code + PKCE subset, client registry
│   ├── audit/                     # application audit hypertable writer (uses Freya redaction)
│   ├── email/                     # Sender interface; smtp/, logsink/ (dev)
│   ├── httpapi/                   # console/public handlers, OpenAPI validation, error encoder
│   └── grpcapi/                   # auth.v1 service implementation (Freya SecurityChain applies)
├── pkg/authclient/                # Go library for downstream services: offline JWT verify + revocation feed
├── console/                       # Vue 3 + Vuetify + TS (Vite); built dist embedded via go:embed
│   ├── src/{app,router,stores,api,views,components,composables}
│   ├── tests/unit (Vitest)  tests/e2e (Playwright)
│   └── package.json, vite.config.ts, tsconfig.json
├── deploy/compose.yaml            # timescaledb, valkey, openfga, mailpit for dev/e2e
├── tests/
│   ├── contract/                  # OpenAPI/proto/FGA-model contract tests
│   ├── integration/               # testcontainers: full flows, negative matrix, revocation timing
│   └── fuzz/
└── docs/                          # dependencies.md, security-model.md, operations.md
```

**Structure Decision**: `services/auth` is a separate Go module with a `replace`
directive to the framework so it can be cut out into its own repository by changing
one line. Inside it, packages are organised by aggregate (tenant, user, session, token,
authz…) rather than by layer, each owning its store repository and tests. The console
is a Vite SPA embedded into the binary for single-artifact deployment, while remaining
independently buildable and testable. The browser-facing listener is added to the
framework (`transport/edge`) rather than to the service because every future
user-facing Freya service needs the same hardened edge.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| #1 Browser-facing listener without client certificates (`transport/edge`, server-auth TLS 1.3) | Browsers cannot present SPIFFE mTLS identities; the console and the client-app sign-in flow must be reachable from browsers | Terminating public TLS at an external ingress/proxy keeps the framework pure but moves a security-critical boundary (headers, CSRF, rate limits) outside tested code and makes the service undeployable/testable on its own; the edge listener keeps TLS 1.3 only, never plaintext, and is the single reviewed place for browser hardening |
| #2 External authorization engine (OpenFGA server + SDK) | User directive; FR-014–FR-017 need custom roles/permissions with sub-5-second propagation and a path to relationship-based authorization for other services | An in-process RBAC table would be simpler for v1 but would be replaced as soon as any service needs relationship/resource-level checks; OpenFGA is pinned, isolated behind `internal/authz`, and the model is a contract |
| #3 OAuth 2.1 authorization-code + PKCE subset (`internal/oauth`) | FR-023: client applications must be able to send a user to sign in and receive the proof of identity back | A custom redirect flow is not smaller than the standard subset and would not work with existing client libraries; only the code+PKCE grant with registered redirect URIs is implemented (no implicit, no password grant, no dynamic registration) |
