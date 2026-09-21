# Constitution Compliance Review — services/auth

**Reviewed**: 2026-09-16 · **Scope**: `services/auth`, `transport/edge`, framework additions (`App.AddServer`, `edge.ClientIP`, `testrt.NewTB`)

## I. Secure by Default

- [x] Edge listener: TLS 1.3 only, server certificate required in production, self-signed only when `env != production` and audited (`insecure_mode_enabled`).
- [x] Cookies `__Host-session`/`__Host-csrf`: Secure, HttpOnly (session), SameSite=Strict, Path=/.
- [x] Tokens: EdDSA pinned, ≤ 15 min, no PII; keys sealed with the KEK; JWKS never exports private material (`TestRotationStatesAndJWKS`).
- [x] Production config refuses plaintext Valkey/OpenFGA/SMTP, weak `sslmode`, missing edge certificate (`config.Validate`).
- [x] Passwords argon2id; TOTP seeds and outbox payloads envelope-encrypted; recovery/invite tokens and session secrets stored hashed.

## II. Zero Trust Service Communication

- [x] `auth.v1` served only on the Freya mTLS channel; `deploy/policy.yaml` scopes operations per service; `Introspect` and `RegisterPermissions` record the SPIFFE ID.
- [x] Downstream verification is offline with the revocation feed; stale feed fails closed (`TestRevocationFeedAndFailClosed`).
- [x] The example downstream registers its permissions and asks `Check` per request.

## III. Boundary Validation & Defense in Depth

- [x] Every browser request validated against the OpenAPI document; unknown fields refused; bodies bounded twice (edge + handler).
- [x] Tenant guard on every service call (`tenantctx.Guard`), tenant-prefixed FGA objects refused before any call, PostgreSQL RLS with a role without `BYPASSRLS` (`TestCrossTenantMatrix`).
- [x] Identifiers (slugs, permission refs, object ids, tokens, JWKS, codes) fuzzed (`tests/fuzz`).
- [x] Operators reach a customer tenant only through a reasoned, ≤ 4 h, audited grant.

## IV. Test-First with Security Verification

- [x] Unit, contract, fuzz suites green; negative matrices for sign-in, tokens, roles, OAuth, operators.
- [x] Coverage gate: ≥ 80 % overall (unit-testable packages), 100 % for `internal/{token,session,password,mfa,tenantctx}` (`make cover`).
- [ ] Integration suite (`-tags integration`, Docker) and Playwright e2e/axe: written and vetted, **not executed in this environment** (Docker unavailable) — see `quickstart-results.md`.

## V. Observability & Auditability

- [x] Closed audit vocabulary (data-model.md + `policy_updated`), every security-relevant action emits exactly one event; detail keys redacted defensively.
- [x] Correlation ids and tracing inherited from the Freya chains; edge refusals audited (`limit_exceeded`, `csrf_refused`, `insecure_mode_enabled`).
- [x] Redaction scan test and script cover logs, audit details, outbox payloads and error bodies.

## VI. Supply Chain Integrity & Minimal Dependencies

- [x] `docs/dependencies.md` justifies every module; `go mod verify` clean for both modules; `govulncheck`: 0 called vulnerabilities (1 uncalled advisory documented); `npm audit`: 0.
- [x] Generated code (`buf`, `openapi-typescript`) committed and reproducible.

## VII. Simplicity & Explicit Configuration

- [x] One YAML configuration with `Default()`, `Validate()`, `Warnings()`; no hidden defaults for security settings.
- [x] SQL bindings separated from security logic (`*db` packages); in-memory doubles only in tests.

## Findings

1. **Open**: integration and e2e suites need a Docker-capable runner before release (constitution IV).
2. **Accepted**: `golang.org/x/crypto` advisory GO-2026-5932 is not reachable from this code; tracked in `docs/dependencies.md`.
