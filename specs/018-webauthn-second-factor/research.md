# Research: Security Keys (WebAuthn) as a Second Factor (018)

Evidence from go-tangra-auth `main` (v4.2.1 + group change) and the v3 code
(go-tangra-portal admin-service, go-tangra-frontend admin app).

## Current state

- **v4 second factor** is TOTP only: `internal/mfa` (20-byte seed sealed with
  AD `mfa:<uid>`, skew ±1, replay blocked via `mfa_last_counter`, 10 recovery
  codes `XXXXX-XXXXX` hashed), users columns `mfa_enabled`, `mfa_secret_enc`,
  `mfa_last_counter`, table `recovery_codes`.
- **Sign-in** (`internal/user/signin.go`): `Start` verifies the password, and
  for `u.MFAEnabled` stores a JSON challenge `{TenantID, UserID, IPHash, UA,
  Roles, Operator, Policy}` in Valkey (`ChallengeKey(HashToken(id))`, 5 min)
  and answers `mfa_required`; `CompleteMFA` verifies the code, counts failures
  in `fail:<uid>`, locks at the policy threshold, establishes the session with
  `amr` `["pwd","otp"|"recovery"]` (stored in `sessions.amr`, JWT `amr`, audit
  `signin_ok.details.amr`).
- **Enrolment/management**: `POST /api/v1/me/mfa/enroll|confirm|disable|
  recovery-codes`; console `MfaEnrol.vue`, `MfaChallenge.vue`, `Account.vue`,
  `useMfa.ts`, `RecoveryCodes.vue`. Tenant policy `mfa_required` (forced for
  the platform tenant) is advisory (`mfa_setup_required`, console guard).
- **Recovery**: break-glass `authsvc reset-user` (`store.ResetCredentials`);
  no admin MFA reset in the API.
- **Gateway mode**: the browser origin is the configured `issuer`
  (production `https://portal.infra.verax.net:8443`); CSP/Permissions-Policy
  from the edge headers do not restrict `publickey-credentials-*`.
- **No WebAuthn library** in `go.mod`.
- **v3** used `github.com/go-webauthn/webauthn` v0.15, credentials as JSON in
  `sys_user_credentials`, sessions in Redis (10 min / 5 min), 4-byte user
  handle = numeric user id, backup codes, no admin reset, and had the gaps
  listed in the spec (no re-auth to remove, no rate limit, backup codes not
  issued for key-first users, names not shown, clone warning ignored).

## Decisions

### D1 — Library
**Decision**: `github.com/go-webauthn/webauthn` v0.18.2 (BSD-3-Clause).
**Rationale**: the reference Go implementation (formerly duo-labs), used by v3,
actively maintained, implements the W3C Level 3 verification steps (RP ID
hash, origin, challenge, flags, counters, COSE keys). Writing CBOR/COSE and
signature verification ourselves would violate Constitution VI ("no custom
cryptography").
**Transitive deps** (11): fxamacker/cbor/v2, x448/float16, go-webauthn/x,
google/go-tpm (TPM attestation types), golang-jwt/jwt/v5 (already used),
google/uuid, go-viper/mapstructure/v2, tinylib/msgp + philhofer/fwd, x/crypto,
x/sys (already present). All pinned in go.sum; `govulncheck` gate.
**Alternatives**: hand-rolled verification (rejected: custom crypto); a
browser-only solution (impossible: verification must be server-side).

### D2 — Relying party configuration
**Decision**: new `webauthn:` config block: `rp_id` (default: host of
`issuer`), `origins` (default: origin of `issuer`, e.g.
`https://portal.infra.verax.net:8443`), `display_name` (default `mfa.issuer`,
i.e. `Tangra`), `user_verification` `preferred` (default) | `required`,
`timeout_seconds` (default 300, 30–600), `enabled` (default true when the
issuer is https). Validated at start: rp_id must equal or be a registrable
parent of every origin's host; origins must be https except
`http://localhost` outside production.

### D3 — Storage
**Decision**: migration `0010_webauthn.sql`:
- table `webauthn_credentials` (see data-model.md), RLS like
  `recovery_codes`, grants to `auth_app`;
- column `users.webauthn_handle bytea` (random 32 bytes, created on first
  registration; never the user UUID — privacy, WebAuthn §14.6.1);
- `users.mfa_enabled` keeps meaning "asks for a second step" and becomes true
  when the first factor of any kind exists; TOTP presence is
  `mfa_secret_enc IS NOT NULL`.

### D4 — Ceremony state
**Decision**: Valkey, single-use (GETDEL), 5 minutes:
- registration: `challenge:webauthn:reg:<uid>` holding the library
  `SessionData` + requested name;
- sign-in: `challenge:webauthn:signin:<hash(challenge id)>` created by an
  options call on a pending MFA challenge; the MFA challenge itself is only
  consumed on success or lockout (existing behaviour);
- step-up (confirm removal of an own factor):
  `challenge:webauthn:stepup:<uid>`.
Each record is bound to the user id and ceremony type (SR-001).

### D5 — Sign-in flow
**Decision**: `Start` unchanged except the `mfa_required` answer lists
`mfa_methods` (`webauthn`, `totp`, `recovery`) of the user. New endpoints
`POST /api/v1/signin/mfa/webauthn/options {challenge}` (assertion options with
the user's keys) and `POST /api/v1/signin/mfa/webauthn {challenge,
credential}` (same result as `/signin/mfa`). Failures go through the same
path as a wrong code (fail counter, lockout, `signin_failed` reason
`mfa_failed`). Success: `amr ["pwd","hwk"]` (RFC 8176), updates sign count,
`last_used_at`, backup flags.

### D6 — Cloned authenticator
**Decision**: on a counter regression (`CloneWarning`) refuse, set
`clone_flagged_at`, audit `mfa_clone_suspected`, count the failure. A flagged
key stays refused until removed and re-registered. Keys reporting counter 0
are not flagged (library semantics).

### D7 — Recovery codes and last-factor rules
**Decision**: a shared helper issues 10 codes when the user had no factor
before (fixes the v3 bug); removing the last factor is refused under
`mfa_required`, otherwise sets `mfa_enabled=false` and deletes unused codes
(same as TOTP disable today).

### D8 — Re-confirmation for removal
**Decision**: `DELETE /api/v1/me/mfa/webauthn/{id}` with body `{code}` (TOTP
or recovery) or `{credential}` (assertion from a step-up options call).
Wrong confirmation counts toward the same lockout counter.

### D9 — Admin view and reset
**Decision**: `GET /api/v1/admin/users/{id}/mfa` and
`POST /api/v1/admin/users/{id}/mfa/reset`, `users:manage`, same privilege
rules as deactivate. Reset deletes TOTP, keys, recovery codes, sets
`mfa_enabled=false`, revokes sessions; audit `mfa_reset`. `reset-user` (CLI)
also deletes `webauthn_credentials`.

### D10 — Parsing bounds
**Decision**: 64 KiB body limit on WebAuthn routes; parse through
`protocol.ParseCredentialCreationResponseBody` /
`ParseCredentialRequestResponseBody` behind a size check; fuzz both entry
points (tests/fuzz). Credential id ≤ 1023 bytes, transports ≤ 8, name ≤ 64.

### D11 — Console
**Decision**: composable `useWebAuthn.ts` (`navigator.credentials` with
`parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` / `toJSON()`
when available, base64url fallback); `MfaEnrol.vue` offers "Authenticator app"
or "Security key"; `Account.vue` "Second factors" card (TOTP + keys: add,
rename, remove with confirmation); `MfaChallenge.vue` method switch (key
first when available); admin `UserDetail.vue` security section with reset.
No CSP change; unsupported browsers see an explanation.

### D12 — Deployment
**Decision**: no required config change (defaults from `issuer`);
go-tangra-docker `PRODUCTION.md` notes that keys are bound to `PUBLIC_HOST`
and must be re-registered if it changes.

## Threat model (STRIDE)

| Threat | Vector | Mitigation |
|---|---|---|
| Spoofing | Phishing site relays the ceremony | Origin + RP ID hash verified (D2) |
| Spoofing | Key registered to another account | Registration session bound to the signed-in user (D4) |
| Tampering | Modified authenticator data / flags | Library verification; user presence required; UV per config |
| Tampering | Cloned key | Counter regression → refuse + flag + audit (D6) |
| Repudiation | Who added/removed a key or reset factors | `mfa_enrolled` / `mfa_removed` / `mfa_reset` audit |
| Information disclosure | User handle reveals identity | Random 32-byte handle (D3) |
| Information disclosure | Which users have keys | Methods only after a correct password; admin view needs users:manage |
| Denial of service | Oversized / nested responses | 64 KiB limit, bounded fields, fuzzed parsing (D10) |
| Denial of service | Brute force on the second step | Shared rate limit + lockout (D5) |
| Elevation of privilege | Hijacked session removes the victim's key | Removal requires a current factor (D8) |
| Elevation of privilege | Admin resets a more privileged user | Same privilege check as deactivate (D9) |
