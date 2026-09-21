# Quickstart: Multi-Tenant Authentication & Authorization Service

Validation guide proving the feature end-to-end. Contracts:
[console-api.openapi.yaml](contracts/console-api.openapi.yaml),
[auth.v1.proto](contracts/auth.v1.proto), [token.md](contracts/token.md),
[authorization-model.fga](contracts/authorization-model.fga),
[edge-listener.md](contracts/edge-listener.md).

## Prerequisites

- Go 1.25+, Node 22 LTS, Docker (for TimescaleDB, Valkey, OpenFGA, mailpit)
- `make testca` from the repository root (SPIFFE dev identities for the service and a
  demo downstream service)

## 1. Stack and gates

```bash
cd services/auth
docker compose -f deploy/compose.yaml up -d       # timescaledb :5432, valkey :6379, openfga :8081(grpc)/:8080(http), mailpit :8025
make lint vuln test cover                         # Go gates (coverage ≥80 %, 100 % in token/session/password/mfa/tenantctx)
(cd console && npm ci && npm run lint && npm run test:unit && npm run build)
```

Expected: all green; `make cover` prints the five 100 % packages.

## 2. First start: platform tenant and operator (US5)

```bash
go run ./cmd/authsvc --config deploy/dev.yaml bootstrap --operator-email op@example.org
go run ./cmd/authsvc --config deploy/dev.yaml
```

Expected: migrations applied (goose), OpenFGA store + model written (id logged),
`platform` tenant created, invitation email visible in mailpit
(http://localhost:8025), edge listener on https://localhost:8443 with a self-signed
dev certificate and an `insecure_mode_enabled reason=local_dev` audit line.

## 3. Operator creates a tenant; owner signs in (US5 → US1)

1. Open https://localhost:8443/console, accept the operator invitation from mailpit,
   set a password, enrol TOTP (operators must).
2. Operators → Tenants → Create `acme` with owner `owner@acme.test`.
3. Accept the owner invitation from mailpit; sign in as `acme / owner@acme.test`.

Expected: console home shows tenant `acme`, role `owner`; `GET /api/v1/session`
returns the roles; `POST /api/v1/session/token` returns a JWT whose header has
`alg=EdDSA` and a `kid` present at `/.well-known/jwks.json`.

## 4. Downstream service verifies offline (US1, SC-004)

```bash
go run ./examples/downstream --config deploy/downstream.yaml   # uses pkg/authclient over the Freya channel
curl -k https://localhost:8443/api/v1/session/token ... | jq -r .access_token > /tmp/at
grpcurl -cert ... -H "authorization: Bearer $(cat /tmp/at)" downstream:9443 demo.v1.Demo/WhoAmI
```

Expected: `WhoAmI` returns user id, tenant `acme`, roles; the downstream log shows
`token verified offline kid=…`; `authclient` metrics show 0 introspection calls.

## 5. Negative sign-in matrix (US1/US2, SC-006)

```bash
go test ./tests/integration -run 'TestSigninMatrix|TestEnumerationTiming' -v
```

Expected: unknown email / wrong password / suspended tenant → identical 401
`{"reason":"invalid_credentials"}` with response-time spread < 10 %; 10 failures →
423 `locked`; cross-tenant sign-in (`globex` + acme credentials) → 401; each case
produces exactly one `signin_failed`/`lockout` audit row.

## 6. Administration and cross-tenant isolation (US2, SC-002)

```bash
go test ./tests/integration -run 'TestAdminFlows|TestCrossTenantMatrix' -v
```

Expected: invite → accept → role assign → deactivate → force sign-out each reflected
in the next sign-in/decision and in `/api/v1/admin/audit`; every cross-tenant
attempt (guessed ids, tokens from another tenant, admin of another tenant) → 404/403
plus `cross_tenant_refused`, with RLS blocking the query even when the handler guard
is bypassed in the test harness.

## 7. Authorization decisions (US3, SC-005)

```bash
go test ./tests/integration -run 'TestAuthzDecisions|TestSelfEscalation' -v
go test ./tests/integration -run xxx -bench BenchmarkCheck -benchtime 10s
```

Expected: custom role `auditor` with `invoices:read` → allow with
`reason=role:auditor`; `invoices:write` → deny `no_permission`; deactivated user →
deny `user_inactive`; role change visible within 5 s; admin granting themselves an
owner-only permission → 403 `self_escalation`; p95 < 20 ms at 1,000 concurrency.

## 8. Self-service security (US4)

```bash
go test ./tests/integration -run 'TestPasswordChange|TestMFA|TestRecovery|TestSessionsSelf' -v
```

Expected: password change ends other sessions; TOTP required after enrolment,
recovery codes single-use; recovery link single-use and expiring, 202 regardless of
existence; revoking one session leaves the other working.

## 9. Revocation propagation and key rotation (SC-003, SC-007)

```bash
go test ./tests/integration -run 'TestRevocationPropagation|TestKeyRotation' -v -timeout 20m
```

Expected: force sign-out / deactivation / tenant suspension rejected by the
downstream verifier within 10 s; three rotations under load with 0 verification
errors; retired keys stay published until the last token expires.

## 10. Console end-to-end and accessibility (SC-001, SC-009)

```bash
(cd console && npx playwright test)      # against the running dev stack
```

Expected: invitation → first sign-in flow < 2 min scripted; sign-in with TOTP < 30 s;
axe reports no critical/serious issues on sign-in, users, roles, audit, account
screens; CSP violations = 0 in the browser console.

## 11. Redaction and headers

```bash
make redaction-scan                      # scans logs, audit rows, email outbox, error bodies
go test ./tests/contract -run 'TestEdgeHeaders|TestCSRFMatrix|TestNoPlaintextEdge' -v
```

Expected: 0 secret markers (password hashes, TOTP seeds, session cookies, tokens,
signing keys); all security headers present; CSRF matrix refused with `csrf`;
plaintext and TLS 1.2 refused at the edge.

## Done when

Sections 1–11 pass on a clean checkout with the compose stack running.
