# Contract: HTTP API (018)

All under `/api/v1`, CSRF double-submit as the rest of the console API, body
limit 64 KiB on the WebAuthn routes. Credential JSON follows the W3C JSON
serialization (base64url fields) produced by `PublicKeyCredential.toJSON()`.

## Sign-in

`POST /signin` — unchanged; the `mfa_required` answer adds
`"mfa_methods": ["webauthn","totp","recovery"]` (only the user's methods;
`recovery` whenever unused codes remain).

`POST /signin/mfa/webauthn/options` `{challenge}` →
`200 {"publicKey": PublicKeyCredentialRequestOptions}` (allowCredentials =
user's non-flagged keys, userVerification per config, timeout) |
`401 invalid_challenge` | `423 locked` | `429 rate_limited`.

`POST /signin/mfa/webauthn` `{challenge, credential}` → same success body as
`/signin/mfa` (session + CSRF cookies, `mfa_setup_required`) |
`401 mfa_failed` (counts toward lockout) | `401 key_flagged` |
`423 locked` | `400 invalid_request`.

`POST /signin/mfa` `{challenge, code}` — unchanged (TOTP or recovery).

## Account (signed-in user)

`GET /me/mfa` → `{"totp": bool, "keys": [{id, name, created_at,
last_used_at, flagged}], "recovery_codes_left": n, "required": bool}`.

`POST /me/mfa/webauthn/register/options` `{name}` →
`200 {"publicKey": PublicKeyCredentialCreationOptions}` (excludeCredentials =
user's keys; attestation "none"; residentKey "discouraged"; UV per config) |
`409 name_taken` | `409 key_limit`.

`POST /me/mfa/webauthn/register` `{credential}` →
`201 {"key": {...}, "recovery_codes": [..]?}` (codes only for the first
factor) | `400 invalid_request` | `401 registration_failed` |
`409 already_registered`.

`PATCH /me/mfa/webauthn/{id}` `{name}` → `200 {key}` | `409 name_taken` |
`404 not_found`.

`POST /me/mfa/stepup/options` → `200 {"publicKey": request options}`.

`DELETE /me/mfa/webauthn/{id}` `{code?} | {credential?}` → `204` |
`401 confirmation_failed` (counts toward lockout) |
`409 last_factor_required`.

Existing `/me/mfa/enroll|confirm|disable|recovery-codes` unchanged; `disable`
(TOTP) keeps `mfa_enabled` when keys remain.

## Admin (`users:manage`)

`GET /admin/users/{id}/mfa` → `{"totp": bool, "keys": [{name, created_at,
last_used_at, flagged}], "recovery_codes_left": n}` (no credential ids, no
key material).

`POST /admin/users/{id}/mfa/reset` → `204` | `403 forbidden` (target more
privileged / self) | `404 not_found`.

## Audit events

| Type | When | Details (never key material) |
|---|---|---|
| `mfa_enrolled` | key registered | `method: "webauthn"`, `aaguid` |
| `mfa_removed` | key removed | `method: "webauthn"`, `reason: "user"` |
| `mfa_reset` | admin reset | `target`, `methods` |
| `mfa_clone_suspected` | counter regression | internal key id |
| `signin_ok` | success | `amr: ["pwd","hwk"]` |
| `signin_failed` | key failure | `reason: "mfa_failed"` |
