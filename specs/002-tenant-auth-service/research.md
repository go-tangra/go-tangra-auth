# Research: Multi-Tenant Authentication & Authorization Service

**Feature**: 002-tenant-auth-service | **Date**: 2026-09-15

All Technical Context unknowns are resolved below. Versions were checked on
2026-09-15 (Go module proxy, npm registry).

## 1. Service packaging and location

**Decision**: `services/auth` is an independent Go module
(`github.com/go-freya/freya/services/auth`, `go 1.25.0`) with
`replace github.com/go-freya/freya => ../..`. Its public contracts (proto, OpenAPI,
OpenFGA model, token format) live in `services/auth/api` and are copied from this
feature's `contracts/`. Moving to a separate repository = delete the `replace`
line and pin a Freya version.

**Rationale**: user directive ("later moved to a separate repo"); a separate module
also keeps the service's dependencies (pgx, OpenFGA SDK, jwt…) out of the framework's
graph (Principle VI).

**Alternatives**: a package inside the framework module (rejected: pollutes the core
dependency graph; cannot be split without history surgery).

## 2. Browser-facing transport

**Decision**: add `transport/edge` to the framework: a server-authenticated TLS 1.3
listener (certificate/key from files with hot reload, or ACME later) that runs the
non-security part of Freya's chain (recover, correlation, tracing, instrumentation),
then edge-specific middleware: strict security headers (CSP `default-src 'self'`,
`frame-ancestors 'none'`, HSTS, `Referrer-Policy: no-referrer`,
`Permissions-Policy` minimal), CSRF protection (double-submit cookie
`__Host-csrf` + `X-CSRF-Token` header on every state-changing request, plus
`Origin`/`Sec-Fetch-Site` checks), per-IP and per-route token-bucket rate limits
(Valkey-backed when configured, in-memory fallback), and the same body/header limits.
There is no peer identity at the edge; the auth service establishes the end user from
the session cookie in its own middleware.

**Rationale**: browsers cannot hold SPIFFE identities; Constitution Principle I still
holds (TLS 1.3 only, no plaintext, secure defaults) and the boundary is in one tested
package. Justified in plan.md Complexity Tracking #1.

**Alternatives**: external ingress terminating TLS and forwarding over mTLS (rejected
for now: moves CSRF/header/rate-limit hardening out of tested code; can still be put in
front of the edge listener in production).

## 3. Proof of identity (tokens) and sessions

**Decision**:
- **Access token**: JWT, `alg=EdDSA` (Ed25519), lifetime 15 min (tenant policy may
  shorten). Claims: `iss` (service URL), `sub` (user id), `tid` (tenant id), `sid`
  (session id), `roles` (built-in + custom role slugs), `amr` (`pwd`, `otp`), `iat`,
  `nbf`, `exp`, `jti`, header `kid`. No PII beyond `sub`; email is not in the token.
- **Session**: opaque 256-bit id in cookie `__Host-session` (`Secure; HttpOnly;
  SameSite=Strict; Path=/`), state in Valkey (`sess:<sid>`: user, tenant, created,
  last-seen, amr, ip/ua hash) with TTL = tenant idle timeout, and a durable row in
  TimescaleDB for listing/audit. Refresh: `POST /api/v1/session/token` mints a new
  access token from a live session; the browser never stores long-lived secrets.
- **Keys**: Ed25519 pairs generated in-service, private keys envelope-encrypted with a
  KEK from the secrets provider (`AES-256-GCM`, `crypto/cipher`), stored in
  `signing_keys`. Rotation every 24 h: new key becomes `active`, previous `retiring`
  for 30 min (> max token lifetime + skew), then `retired` (still published until the
  last token expires, then removed from JWKS). JWKS at `/.well-known/jwks.json` and
  gRPC `Keys.List`.
- **Revocation** (FR-011, SC-003): revoking a session/user/tenant writes
  `rev:sid:<sid>` / `rev:user:<uid>` / `rev:tenant:<tid>` with TTL = max token
  lifetime + skew, and appends to a revocation log (TimescaleDB, `revocations`
  hypertable, 1-hour retention). Downstream services use `pkg/authclient`, which
  verifies tokens offline and polls `Sessions.RevokedSince(cursor)` every 5 s
  (or subscribes via server streaming); a token is rejected if its `sid`/`sub`/`tid`
  appears with a revocation time ≥ token `iat`. Worst-case propagation = poll interval
  + clock skew < 10 s.

**Rationale**: EdDSA keys are small and fast; JWT with pinned algorithm avoids the
classic confusion attacks; opaque cookie sessions keep browser secrets revocable and
out of JavaScript; short tokens + a cheap revocation feed satisfy SC-003/SC-004
without per-request introspection.

**Alternatives**: PASETO (rejected: fewer client libraries for downstream teams);
opaque access tokens with introspection (rejected: violates SC-004); refresh tokens in
the browser (rejected: larger theft surface than the HttpOnly session cookie).

## 4. Password and second factor

**Decision**: argon2id (`golang.org/x/crypto/argon2`) with OWASP parameters
(m = 19 MiB, t = 2, p = 1), per-user 16-byte salt, versioned hash string
(`$argon2id$v=19$m=19456,t=2,p=1$…`) so parameters can be raised with rehash-on-login.
Tenant password policy: min length (default 12), no composition rules, breached-list
check optional (offline k-anonymity list is out of scope). TOTP (`pquerna/otp`,
SHA-1/6 digits/30 s for authenticator-app compatibility, ±1 step window,
replay-protected by remembering the last accepted counter). TOTP seeds envelope-
encrypted at rest; 10 single-use recovery codes stored as argon2id hashes.
Constant-time comparisons everywhere; enumeration-safe flows pad response time to a
fixed floor (SC-006).

**Alternatives**: bcrypt (rejected: argon2id mandated by constitution); WebAuthn
passkeys (deferred: strong candidate for a later feature).

## 5. Authorization engine: OpenFGA

**Decision**: OpenFGA server v1.20.0 as a separate container (own PostgreSQL database
on the TimescaleDB instance), reached via gRPC with TLS and a pre-shared API token from
the secrets provider; SDK `github.com/openfga/go-sdk` v0.8.2. One store, one
authorization model (contracts/authorization-model.fga) with tenant scoping encoded in
object identifiers:

- `tenant:<tid>` with `owner`, `admin` (or owner), `member` (or admin)
- `role:<tid>/<slug>` with `tenant` and `assignee: [user]`
- `permission:<tid>/<resource>~<action>` with `granted: [role#assignee]`

Decision (FR-016): `Check(user:<uid>, granted, permission:<tid>/<res>~<act>)` after the
service verifies the caller's tenant equals `<tid>` and the user is active. Writes are
made only by `internal/authz` (never by other services). Role assignment writes
`role:…#assignee`; permission grants write `permission:…#granted`. Built-in roles are
seeded per tenant. Decisions are cached in-process for 2 s and in Valkey for 2 s
keyed by tenant/user/permission; role changes bump a per-tenant version that busts the
cache (SC-005 ≤ 5 s).

**Rationale**: user directive; relationship model scales to resource-level checks for
other services later; tenant id in every object id plus the caller-tenant guard gives
hard isolation.

**Alternatives**: in-process RBAC (rejected, see Complexity #2); Casbin (rejected:
no server-side relationship engine, weaker multi-tenant story); one OpenFGA store per
tenant (rejected: 1,000 stores complicate operations and model upgrades).

## 6. Storage: TimescaleDB

**Decision**: PostgreSQL 16 + timescaledb, accessed with pgx v5 (no ORM). Regular
tables for aggregates; hypertables for `auth_audit_events` (retention 400 days,
compression after 30 days), `signin_attempts` (retention 30 days) and `revocations`
(retention 1 hour). Migrations with goose (embedded SQL, run on start with an
advisory lock). Row-level security on every tenant-owned table with policies on
`current_setting('app.tenant_id')`; the service sets it with `SET LOCAL` in each
transaction from the verified tenant context; the operator path sets a special
`app.operator_grant` only inside an active, audited grant (SR-006). The application
role cannot bypass RLS.

**Alternatives**: separate schema per tenant (rejected: migrations × 1,000 tenants);
separate database per tenant (rejected: connection-pool explosion).

## 7. Valkey usage

**Decision**: valkey-go v1.0.78 with TLS and ACL user. Keys: sessions, revocation
marks, lockout/rate-limit counters (sliding window via `INCR`+`EXPIRE`), decision
cache, and pub/sub `auth:revoked` to fan revocations out to other instances. Valkey
is a cache/state accelerator, not a source of truth: session rows and revocation log
in TimescaleDB allow rebuilding it after loss (sessions are simply re-authenticated).

## 8. Console (Vue 3 + Vuetify, TypeScript)

**Decision**: Vite 8 + Vue 3.5 + Vuetify 4.2 + TypeScript 7 (strict), Pinia 4 for
state, vue-router 5 with route guards by role, OpenAPI-generated TypeScript client
(`openapi-typescript` types + a thin fetch wrapper that adds the CSRF header),
i18n-ready strings, WCAG 2.2 AA via Vuetify semantics + axe checks in Playwright.
Served by the service from `go:embed console/dist` under `/console/` with CSP nonces
for Vuetify's runtime styles; no inline scripts. Dev: Vite proxy to the edge listener.

**Alternatives**: separate static hosting (rejected for now: one deployable artifact;
can be split later since the console only talks to the OpenAPI contract).

## 9. Client-application sign-in (FR-023)

**Decision**: OAuth 2.1 authorization-code grant with PKCE (S256) for registered
clients (`client_applications` table: client id, tenant, allowed redirect URIs,
public/confidential). Endpoints `/authorize` (renders the console sign-in; tenant
resolved from the client) and `POST /api/v1/oauth/token` (code exchange → access token
+ session cookie for the console origin). No implicit, password or client-credentials
grants; `state` and exact redirect-URI matching required.

## 10. Email delivery

**Decision**: `email.Sender` interface; `smtp` implementation (implicit TLS or
STARTTLS required, credentials from the secrets provider) and `logsink` for
development; dev compose ships mailpit for e2e tests. Sends are queued in
TimescaleDB (`outbox`) and retried; administrators can resend invitations.

## 11. Dependency justification (core module deltas)

| Dependency | Purpose | Alternatives rejected |
|------------|---------|------------------------|
| `openfga/go-sdk` v0.8.2 | authorization engine client | raw gRPC to OpenFGA (re-implements the SDK) |
| `jackc/pgx/v5` v5.11.0 | PostgreSQL driver + pool | database/sql + lib/pq (no COPY, weaker types) |
| `pressly/goose/v3` v3.28.0 | embedded migrations | golang-migrate (heavier), hand-rolled |
| `valkey-io/valkey-go` v1.0.78 | Valkey client (RESP3, client-side caching) | go-redis (larger API surface) |
| `golang-jwt/jwt/v5` v5.3.1 | JWT with algorithm pinning | lestrrat jwx (larger), hand-rolled (prohibited) |
| `golang.org/x/crypto` v0.57.0 | argon2id | none (constitution-approved source) |
| `pquerna/otp` v1.5.0 | TOTP/HOTP | hand-rolled (RFC 6238 is simple but the library is audited) |
| `google.golang.org/protobuf`, `grpc` | via Freya | — |

Console: Vue/Vuetify/Vite/Pinia/vue-router pinned by lockfile; `npm audit` in CI.

## 12. Threat model (STRIDE)

| Threat | Mitigation | Verified by |
|--------|------------|-------------|
| **S** credential stuffing / brute force | argon2id, per-account + per-IP rate limits, tenant lockout threshold, TOTP | `TestLockout`, `TestRateLimit` |
| **S** account enumeration | identical responses + padded timing for sign-in/recovery/invite | `TestEnumerationTiming` (SC-006) |
| **S** token forgery / alg confusion | EdDSA only, `kid` bound to published keys, `iss/aud/exp/nbf` enforced in `pkg/authclient` | `TestTokenNegativeMatrix` |
| **T** cross-tenant access via ids | tenant context guard on every handler + RLS policies + tenant-prefixed FGA objects | `TestCrossTenantMatrix` (SC-002) |
| **T** CSRF / XSS on console | double-submit CSRF + Origin checks, strict CSP, HttpOnly cookies, no inline scripts | `TestEdgeHeaders`, Playwright axe/CSP checks |
| **R** admin actions | application audit hypertable with actor/subject/tenant/origin | `TestAuditCoverage` (SC-008) |
| **I** secrets in logs/DB | Freya redaction, envelope encryption for TOTP seeds and signing keys, hashes only for passwords/recovery codes/invite tokens | `TestRedactionScan`, schema review |
| **D** login floods | edge rate limits, Freya body/stream limits, Valkey counters | `TestRateLimit` |
| **E** admin self-escalation / last owner removal | grants limited to permissions the actor holds; owner invariant in a transaction | `TestSelfEscalation`, `TestLastOwner` |
| **E** operator abuse | operator tenant with mandatory TOTP; time-limited, audited access grants required for in-tenant actions | `TestOperatorGrant` |
| **S/T** stolen session replay after revocation | revocation marks + feed; downstream reject within ≤10 s | `TestRevocationPropagation` (SC-003) |
| **I** key compromise | 24 h rotation, KEK outside the DB, retire/republish schedule | `TestKeyRotation` (SC-007) |
