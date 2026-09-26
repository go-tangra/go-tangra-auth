# Implementation Plan: Security Keys (WebAuthn) as a Second Factor

**Branch**: `018-webauthn-second-factor` | **Date**: 2026-09-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/018-webauthn-second-factor/spec.md`

## Summary

auth gains security keys as a second factor next to TOTP. A new
`internal/webauthn` service wraps `github.com/go-webauthn/webauthn` with the
relying party derived from `issuer`; keys are stored in a new
`webauthn_credentials` table with a random per-user handle. Ceremonies are
single-use Valkey records bound to user and purpose. Sign-in reuses the
existing MFA challenge: new options/verify endpoints share the failure
counter, lockout and audit vocabulary with TOTP and record `amr
["pwd","hwk"]`. Users list, rename and remove keys (removal re-confirmed by a
current factor); recovery codes are issued for the first factor of any kind;
administrators can view a user's methods and reset them. The console gets a
`useWebAuthn` composable and updated enrolment, challenge, account and admin
views.

## Technical Context

**Language/Version**: Go 1.26 (service), TypeScript/Vue 3 (console)

**Primary Dependencies**: go-tangra/v4 framework, pgx/goose, valkey,
`github.com/go-webauthn/webauthn` v0.18.2 (new, research D1),
`@go-tangra/ui` 4.1.1

**Storage**: PostgreSQL (`webauthn_credentials`, `users.webauthn_handle`),
Valkey (ceremony records, rate limits)

**Testing**: `go test` (unit with a software ES256 authenticator, negative
security tests, fuzz on parse wrappers), testcontainers integration, vitest
(stubbed `navigator.credentials`), Playwright with the Chrome virtual
authenticator

**Target Platform**: Linux containers behind the go-tangra gateway

**Project Type**: web service + console SPA (one repo: go-tangra-auth)

**Performance Goals**: ceremony endpoints < 100 ms server time; no change to
sign-in latency for TOTP users

**Constraints**: coverage gate — 100 % for `internal/mfa`, `internal/token`,
`internal/session`, `internal/password`, `internal/tenantctx`,
`internal/ldapdir`; add `internal/webauthn` to the 100 % set (security
package); strict YAML config decoding

**Scale/Scope**: ≤ 10 keys per user; one new package, one migration, ~10
endpoints, 4 console views

## Constitution Check

*GATE: re-checked after Phase 1 design — all PASS.*

- [x] **I. Secure by Default**: user presence always required; attestation
      "none" (privacy); UV "preferred" with "required" as stricter option;
      WebAuthn off automatically on a non-https issuer outside dev.
- [x] **II. Zero Trust**: every new route authenticated (session, pending MFA
      challenge, or `users:manage`) by existing middleware; no bypass.
- [x] **III. Boundary Validation**: 64 KiB bodies, bounded fields, library
      verification of RP ID/origin/challenge/flags, DB CHECK constraints.
- [x] **IV. Test-First**: tasks list tests first per story; negative tests
      (wrong origin, replayed challenge, other user's key, clone signal,
      shared lockout, removal without confirmation); fuzz on both parse
      wrappers; 100 % coverage for `internal/webauthn`.
- [x] **V. Observability**: audit `mfa_enrolled`/`mfa_removed`/`mfa_reset`/
      `mfa_clone_suspected`, `signin_ok.amr` with `hwk`; no key material in
      logs or audit.
- [x] **VI. Supply Chain**: one new direct dependency justified in research
      D1 (11 transitive, pinned); `govulncheck` clean; no custom crypto.
- [x] **VII. Simplicity**: typed `webauthn` config block with derived
      defaults; one package; state in existing stores.
- [x] **Threat Model**: STRIDE in research.md.

## Project Structure

### Documentation (this feature)

```text
specs/018-webauthn-second-factor/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/{http.md,config.md}
├── checklists/requirements.md
└── tasks.md
```

### Source Code (go-tangra-auth)

```text
internal/config/config.go                 # webauthn block, validation, defaults from issuer
internal/store/migrations/0010_webauthn.sql
internal/store/webauthn.go                # credential CRUD, handle, counters
internal/memstore/webauthn.go             # in-memory fake
internal/webauthn/                        # NEW: service (RP, ceremonies, limits), softkey test helper
internal/mfa/mfa.go                       # shared first/last-factor helpers; TOTP disable keeps keys
internal/user/signin.go                   # mfa_methods, WebAuthn completion path, amr hwk
internal/httpapi/{signin,account,admin}.go# new routes (contracts/http.md)
internal/app/{app.go,reset.go}            # wiring; reset-user deletes keys
internal/audit/audit.go                   # mfa_reset, mfa_clone_suspected
tests/fuzz/webauthn_fuzz_test.go
tests/integration/webauthn_test.go
console/src/composables/useWebAuthn.ts
console/src/views/{MfaEnrol,MfaChallenge,Account}.vue
console/src/views/admin/UserDetail.vue
console/src/components/SecurityKeys.vue
console/tests/unit/webauthn.spec.ts, console/tests/e2e/webauthn.spec.ts
docs/operations.md, docs/security-model.md, docs/dependencies.md
```

**Structure Decision**: all in go-tangra-auth; go-tangra-docker only gets a
PRODUCTION.md note (keys bound to PUBLIC_HOST).

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| New dependency with 11 transitive modules | WebAuthn verification (CBOR/COSE, attestation formats, counters) | Hand-written verification is custom cryptography (Constitution VI) |
