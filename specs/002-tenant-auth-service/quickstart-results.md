# Quickstart results — 2026-09-16

Environment: workstation without Docker. Sections that need the compose stack
(TimescaleDB, Valkey, OpenFGA, mailpit) could not be executed end-to-end; the
suites that implement them were compiled and vetted with `-tags integration`
and will run in CI (`auth-service-integration` job).

| § | Scenario | Result |
|---|----------|--------|
| 1 | Stack and gates (`make lint cover fuzz`, console lint/unit) | **PASS** — vet/staticcheck/gosec clean, coverage gate green (100 % on the five security packages), fuzz smoke green, 29 console unit tests green |
| 2 | Bootstrap: platform tenant, operator invitation, MFA mandatory | not executed (Docker); covered by `TestHarnessBootsAndBootstraps`, `TestTenantLifecycle` |
| 3 | Operator creates tenant; owner signs in; token + JWKS | not executed; covered by `TestTenantLifecycle`, `TestTokenLifecycle`, handler tests |
| 4 | Downstream verifies offline | not executed; `examples/downstream` builds; `pkg/authclient` unit-tested (offline verify, refresh cap, feed, fail-closed) |
| 5 | Negative sign-in matrix, timing spread | not executed; `TestSigninMatrix`, `TestEnumerationTiming` written; unit matrix green |
| 6 | Administration and cross-tenant isolation | not executed; `TestAdminFlows`, `TestCrossTenantMatrix` (incl. RLS SQL probe) written; handler tests green |
| 7 | Authorization decisions, escalation, propagation, p95 gate | not executed; `TestAuthzDecisions`, `TestSelfEscalation`, `TestPropagation`, `BenchmarkCheck` + `scripts/authz-gate.sh` written; unit decisions green |
| 8 | Self-service security | not executed; `TestMFA`, `TestPasswordChange`, `TestRecovery`, `TestSessionsSelf` written; handler tests green |
| 9 | Revocation propagation, key rotation | not executed; `TestRevocationPropagation`, `TestKeyRotation` written; ring rotation unit-tested |
| 10 | Console e2e + axe | not executed; Playwright specs in `console/tests/e2e` |
| 11 | Redaction and headers | not executed; `TestRedactionScan`, `TestHardening`, `scripts/redaction-scan.sh` written |

Re-run on a Docker-capable machine:

```bash
make -C services/auth test-integration redaction-scan
services/auth/scripts/authz-gate.sh
(cd services/auth/console && npm run build && npm run test:e2e)
```
