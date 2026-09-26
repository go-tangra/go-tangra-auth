---

description: "Task list for 018 Security Keys (WebAuthn) as a Second Factor"
---

# Tasks: Security Keys (WebAuthn) as a Second Factor

**Input**: Design documents from `specs/018-webauthn-second-factor/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: MANDATORY (Constitution IV). Tests precede implementation in every
phase and must fail first. Negative security tests and fuzz tests are
included for parsing, ceremonies, lockout and authorization.

**Paths**: relative to go-tangra-auth (except T041, go-tangra-docker).

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [ ] T001 Add `github.com/go-webauthn/webauthn` v0.18.2 to `go.mod` (`go get`, `go mod tidy`), record purpose/alternatives/licence/maintenance in `docs/dependencies.md`; run `govulncheck ./...`
- [ ] T002 [P] Add `internal/webauthn` to the 100 % coverage set in `scripts/coverage-gate.sh` / `Makefile`

---

## Phase 2: Foundational (blocking)

### Tests first

- [ ] T003 [P] Config tests in `internal/config/config_test.go`: defaults derived from `issuer` (rp_id host, origin with port), overrides, refusals (rp_id not a parent of an origin host, non-https origin in production, bad user_verification, timeout bounds), `enabled` false on non-https issuer outside dev
- [ ] T004 [P] Store integration tests in `internal/store/webauthn_test.go`: insert/list/rename/delete credential, unique credential_id, unique name per user (case-insensitive), CHECK bounds, sign-count/last-used/flag updates, `webauthn_handle` create-once, cascade on user delete, RLS isolation between tenants
- [ ] T005 [P] Service tests with a software ES256 authenticator in `internal/webauthn/webauthn_test.go` (+ helper `internal/webauthn/softkey_test.go`): registration and assertion happy paths, wrong origin, wrong rp_id hash, replayed/expired/foreign-purpose ceremony, user presence missing, UV required but absent, credential of another user, flagged key, counter regression → flagged, key limit 10, duplicate credential
- [ ] T006 [P] Fuzz targets for the size-bounded parse wrappers (creation and request response bodies) in `tests/fuzz/webauthn_fuzz_test.go`; add to `make fuzz`

### Implementation

- [ ] T007 `webauthn` config block with Validate/Warnings and defaults from `issuer`/`mfa.issuer` in `internal/config/config.go`; dev configs `deploy/{dev,dev-standalone,gateway-mode}.yaml`
- [ ] T008 Migration `internal/store/migrations/0010_webauthn.sql` per data-model.md (table, RLS policy, grants, `users.webauthn_handle`)
- [ ] T009 Store functions in `internal/store/webauthn.go` (+ models) and memstore fake `internal/memstore/webauthn.go`
- [ ] T010 `internal/webauthn` service: relying party from config, ceremony records in Valkey (GETDEL, 5 min, bound to user and purpose), `BeginRegistration/FinishRegistration`, `BeginAssertion/FinishAssertion` (sign-in and step-up), limits, clone handling, parse wrappers with 64 KiB bound
- [ ] T011 Audit types `mfa_reset`, `mfa_clone_suspected` (and `method` detail on `mfa_enrolled`/`mfa_removed`) in `internal/audit/audit.go`
- [ ] T012 Wiring in `internal/app/app.go` (service built when enabled; warning when disabled with existing keys)

**Checkpoint**: foundation tests green; coverage gate includes `internal/webauthn`.

---

## Phase 3: User Story 1 — Register a security key (P1) 🎯 MVP

**Goal**: a signed-in user registers a named key; the first factor issues recovery codes.

**Independent Test**: register with the soft authenticator via the API; key listed; recovery codes returned only for the first factor.

### Tests

- [ ] T013 [P] [US1] Shared factor helper tests in `internal/mfa/mfa_test.go` (keep 100 %): first factor of any kind issues 10 codes; second factor does not replace codes; TOTP disable keeps `mfa_enabled` while keys remain
- [ ] T014 [P] [US1] HTTP tests in `internal/httpapi/webauthn_test.go`: `GET /me/mfa`, `POST /me/mfa/webauthn/register/options` (name validation, name_taken, key_limit), `POST /me/mfa/webauthn/register` (201 with/without codes, already_registered, oversized body 400, CSRF required, unauthenticated 401)
- [ ] T015 [P] [US1] Console tests in `console/tests/unit/webauthn.spec.ts`: `useWebAuthn` JSON ↔ credential conversion (native `toJSON`/`parse*FromJSON` and base64url fallback), unsupported browser message, cancel/timeout message; `MfaEnrol.vue` offers app or key; recovery codes shown once

### Implementation

- [ ] T016 [US1] Factor helpers in `internal/mfa/mfa.go` (first factor → codes; `mfa_enabled` from TOTP ∨ keys)
- [ ] T017 [US1] Routes `GET /me/mfa`, `POST /me/mfa/webauthn/register/options`, `POST /me/mfa/webauthn/register` in `internal/httpapi/account.go` (body limit, audit `mfa_enrolled`)
- [ ] T018 [US1] `console/src/composables/useWebAuthn.ts`, `console/src/api` types, `MfaEnrol.vue` method choice + key registration, `RecoveryCodes.vue` reuse

**Checkpoint**: US1 demonstrable (quickstart step 1).

---

## Phase 4: User Story 2 — Sign in with a security key (P1)

**Goal**: password + key signs in; failures share the lockout; clone signal refused.

**Independent Test**: sign in with password + soft authenticator; session `amr` = pwd,hwk; ten failures (mixed code/key) lock the account.

### Tests

- [ ] T019 [P] [US2] Sign-in service tests in `internal/user/signin_test.go`: `mfa_methods` listing, WebAuthn completion success (`amr` pwd,hwk, last_used_at, sign count), failure counts toward `fail:<uid>` and locks at the threshold shared with TOTP, locked account refused before verification, challenge reuse after success refused, options on an expired/unknown challenge refused, flagged key refused + `mfa_clone_suspected`
- [ ] T020 [P] [US2] HTTP tests: `POST /signin/mfa/webauthn/options` and `/signin/mfa/webauthn` status codes and cookies; rate limiting; recovery code path still works for key-only users
- [ ] T021 [P] [US2] Integration test `tests/integration/webauthn_test.go`: full register → sign out → sign in with key against Postgres/Valkey; audit `signin_ok` details `amr`
- [ ] T022 [P] [US2] Console tests: `MfaChallenge.vue` shows the user's methods, key first, switch to code/recovery, error messages

### Implementation

- [ ] T023 [US2] `mfa_methods` in the `Start` answer and `CompleteWebAuthn` in `internal/user/signin.go` sharing the failure/lockout/audit path
- [ ] T024 [US2] Routes in `internal/httpapi/signin.go`
- [ ] T025 [US2] `MfaChallenge.vue` method switch and key assertion via `useWebAuthn`
- [ ] T026 [US2] Playwright scenario `console/tests/e2e/webauthn.spec.ts` with the Chrome virtual authenticator (register, sign out, sign in)

**Checkpoint**: MVP complete (US1 + US2).

---

## Phase 5: User Story 3 — Manage security keys (P2)

### Tests

- [ ] T027 [P] [US3] Service/HTTP tests: rename (name_taken, not_found, other user's key 404), step-up options, delete with TOTP code / recovery code / key assertion, wrong confirmation counts toward lockout, last factor refused under `mfa_required`, last factor removal without policy clears `mfa_enabled` and unused codes, audit `mfa_removed`
- [ ] T028 [P] [US3] Console tests: `SecurityKeys.vue` list (name, added, last used, flagged), rename, remove with confirmation dialog offering available methods

### Implementation

- [ ] T029 [US3] Routes `PATCH/DELETE /me/mfa/webauthn/{id}`, `POST /me/mfa/stepup/options` in `internal/httpapi/account.go`
- [ ] T030 [US3] `console/src/components/SecurityKeys.vue` and the "Second factors" card in `Account.vue` (TOTP + keys)

---

## Phase 6: User Story 4 — Administrators help a user (P3)

### Tests

- [ ] T031 [P] [US4] HTTP tests: `GET /admin/users/{id}/mfa` (no key material, `users:manage` required), `POST /admin/users/{id}/mfa/reset` (removes TOTP, keys, codes; revokes sessions; audit `mfa_reset`; refused for self / more privileged target / missing permission; cross-tenant 404)
- [ ] T032 [P] [US4] `reset-user` CLI test: keys deleted with the other credentials (`internal/app/reset_test.go`)
- [ ] T033 [P] [US4] Console tests: `UserDetail.vue` security section and reset confirmation

### Implementation

- [ ] T034 [US4] Admin routes in `internal/httpapi/admin.go` (privilege rules as deactivate)
- [ ] T035 [US4] `store.ResetCredentials` / `internal/app/reset.go` delete `webauthn_credentials`
- [ ] T036 [US4] `console/src/views/admin/UserDetail.vue` security section

---

## Phase 7: Polish & Release

- [ ] T037 [P] `docs/operations.md` (security keys, config, relying party bound to the public host, admin reset), `docs/security-model.md` (WebAuthn threats), OpenAPI/schema for the new routes
- [ ] T038 Coverage gate (100 % `internal/webauthn`, `internal/mfa`), `govulncheck`, `go vet`, console lint + unit tests + build
- [ ] T039 Run quickstart.md automated checks; record results in `specs/018-webauthn-second-factor/quickstart-results.md`
- [ ] T040 Release auth (next minor, e.g. 4.3.0) — PR, CI, tag (confirm with the user)
- [ ] T041 go-tangra-docker `PRODUCTION.md`: keys are bound to `PUBLIC_HOST`; re-registration needed if it changes; pin the auth release

---

## Dependencies & Execution Order

- Setup (T001–T002) → Foundational (T003–T012) → US1 (T013–T018) → US2 (T019–T026) → US3 (T027–T030) → US4 (T031–T036) → Polish (T037–T041).
- US3 and US4 depend on US1 (keys must exist); US4 does not depend on US3.
- Console tasks of a story can run in parallel with its backend tasks once the contract (contracts/http.md) is fixed.

### Parallel Opportunities

- T003–T006; T013–T015; T019–T022; T027–T028; T031–T033.

## Implementation Strategy

MVP = US1 + US2 (register and sign in with a key; recovery codes for
key-only users). Then management (US3) and admin reset (US4). Release after
Phase 7; production needs no config change (relying party derived from the
issuer, `portal.infra.verax.net`).
