# Contract: Proof of Identity, Sessions, Revocation

## Access token (JWT)

- Header: `{"alg":"EdDSA","typ":"JWT","kid":"<kid>"}` — `alg` is pinned; any other
  value is rejected before signature verification.
- Claims:

| Claim | Value |
|-------|-------|
| `iss` | issuer URL of this service (e.g. `https://auth.example.org`) |
| `sub` | user id (UUID) |
| `tid` | tenant id (UUID) |
| `sid` | session id (UUID) |
| `roles` | array of role slugs in the tenant (built-in + custom) |
| `amr` | authentication methods: `["pwd"]` or `["pwd","otp"]` |
| `iat`, `nbf`, `exp` | seconds; `exp − iat ≤ 900` (tenant policy may shorten) |
| `jti` | UUIDv7 |
| `aud` | optional client id when minted via the OAuth code flow |

- No email, name or other PII in the token.
- Verification (`pkg/authclient` and any other verifier): `alg == EdDSA`; `kid`
  present in the published keys; signature valid; `nbf − skew ≤ now < exp + skew`
  (skew ≤ 60 s); `iss` matches; `tid` matches the expected tenant when the caller
  scopes by tenant; not revoked (see below).

## Verification keys

- `GET /.well-known/jwks.json` (edge) and `auth.v1.Keys/List` (service channel):
  keys with `state ∈ {active, retiring, retired}`; a key disappears only after the
  last token it could have signed has expired.
- Rotation: 24 h; `retiring` 30 min; verifiers refresh keys every 5 min and on an
  unknown `kid` (with a 1-per-minute cap).

## Session cookie

- `__Host-session=<256-bit random, base64url>`; `Secure; HttpOnly; SameSite=Strict;
  Path=/`. The value is never logged; the server stores only its SHA-256.
- Idle timeout and absolute lifetime from the tenant policy; `POST /api/v1/session/token`
  mints a fresh access token from a live session.

## CSRF

- Cookie `__Host-csrf` (not HttpOnly, `SameSite=Strict`, random 256-bit) issued with
  the session; every state-changing request must carry `X-CSRF-Token` equal to it.
  Additionally `Origin` (or `Sec-Fetch-Site: same-origin`) must match the console
  origin. Missing/mismatching → 403 `{"reason":"csrf"}`.

## Revocation feed

- Entries `{ts, kind, subject_id, tenant_id, reason}` from `auth.v1.Sessions/RevokedSince`
  (poll ≤ 5 s) or `Watch` (stream). A verifier rejects a token when an entry with
  `kind=session ∧ subject_id=sid`, or `kind=user ∧ subject_id=sub`, or
  `kind=tenant ∧ subject_id=tid` has `ts ≥ iat`. Entries are retained 60 min
  (> max token lifetime); a verifier that was offline longer than that must treat
  all tokens as unverifiable until it re-syncs (fail closed).

## Error bodies (edge and console API)

`{"reason": "<closed vocabulary>"}` only. Authentication failures use
`invalid_credentials` regardless of cause (SR-007); lockouts use `locked`;
tenant suspension uses `tenant_suspended`; CSRF uses `csrf`; rate limits `rate_limited`.
