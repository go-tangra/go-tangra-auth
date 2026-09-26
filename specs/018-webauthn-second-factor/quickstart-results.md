# Quickstart results: security keys (018)

Date: 2026-09-26, branch `018-webauthn-second-factor`, workstation
(Go 1.26.8, Node, Chrome via `PW_CHANNEL=chrome`, Docker for testcontainers).

## Automated checks

| Check | Command | Result |
|---|---|---|
| Build, vet, unit tests | `go build ./... && go vet ./... && go test ./...` | pass |
| Lint | `golangci-lint run ./...` (also `--build-tags integration ./tests/integration/`) | 0 issues |
| Coverage gate | `make cover` | total 88.3 %; `internal/webauthn`, `internal/mfa`, `internal/token`, `internal/session`, `internal/password`, `internal/tenantctx`, `internal/ldapdir` 100 % |
| Integration (Postgres/Valkey/OpenFGA) | `go test -tags integration ./internal/store/ ./tests/integration/...` | pass (incl. `TestWebAuthnRepos`, `TestSecurityKeyEndToEnd`, `TestResetUser`) |
| Fuzz (parse wrappers) | `go test -fuzz=FuzzWebAuthnCreation / FuzzWebAuthnAssertion -fuzztime=30s ./tests/fuzz/` | no failures |
| Vulnerabilities | `scripts/vulncheck.sh` | no reachable vulnerabilities |
| Console | `npm run lint`, `npx vitest run` (104 tests), `npm run build` | pass |
| Playwright, Chrome virtual authenticator | `E2E_PLAYWRIGHT=1 PW_CHANNEL=chrome go test -tags integration -run TestWebAuthnPlaywright ./tests/integration/` | pass: register on the account page (10 recovery codes), sign out, sign in with password + key (sign count increases), remove confirmed by the key; axe checks on the account and second-step pages; `mfa_enrolled` / `mfa_removed` audited |

## Quickstart steps covered automatically

1. Register a key, recovery codes for the first factor — Playwright,
   `TestSecurityKeyEndToEnd`, `TestKeyFirstFactorIssuesCodes`.
2. Sign in with password + key, `signin_ok` `amr pwd,hwk` —
   Playwright, `TestSecurityKeyEndToEnd`, `TestSigninWithSecurityKey`.
3. Rename, add a second key, remove confirmed by a key or code —
   `TestRenameAndRemove`, `TestWebAuthnManagementRoutes`, console unit tests.
4. Recovery code when the key is not at hand — `TestSigninWithSecurityKey`
   (key-only user signs in with a recovery code).
5. Admin view and reset — `TestAdminResetMFA`, `TestWebAuthnAdminRoutes`,
   console unit test for `UserDetail.vue`.
6. Wrong address — wrong origin / RP ID refused in
   `TestRegistrationRefusals` and `TestAssertionRefusals`; the console guard
   (`hostMatches`) names the expected address (unit test).

## Not run here

The manual production steps with a physical YubiKey (quickstart "Manual")
need the released service on `portal.infra.verax.net` and an operator
sign-in; they are part of the release (T040).
