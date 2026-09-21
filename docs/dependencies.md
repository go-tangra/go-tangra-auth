# Dependency Justification — services/auth (Constitution Principle VI)

| Dependency | Version | Purpose | Alternatives rejected | Maintenance |
|------------|---------|---------|------------------------|-------------|
| `github.com/go-freya/freya` | local (`replace ../..`) | mTLS transports, identity, service policy, audit, observability, edge listener | — | this repository |
| `github.com/openfga/go-sdk` | v0.8.2 | OpenFGA client (Check/BatchCheck/Write/model bootstrap) | raw gRPC to OpenFGA (re-implements the SDK) | Active (CNCF sandbox) |
| `github.com/jackc/pgx/v5` | v5.11.0 | PostgreSQL/TimescaleDB driver and pool | database/sql + lib/pq (no COPY, weaker types) | Active |
| `github.com/pressly/goose/v3` | v3.28.0 | Embedded SQL migrations with advisory lock | golang-migrate (heavier) | Active |
| `github.com/valkey-io/valkey-go` | v1.0.78 | Valkey client (RESP3) | go-redis (larger surface) | Active |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | JWT with pinned EdDSA | jwx (larger), hand-rolled (prohibited) | Active |
| `golang.org/x/crypto` | v0.57.0 | argon2id | none (constitution-approved) | Go project |
| `github.com/pquerna/otp` | v1.5.0 | TOTP (RFC 6238) | hand-rolled | Active |
| `golang.org/x/image` | v0.46.0 | avatar pipeline: WebP decoding (`webp`) and CatmullRom resampling (`draw`) for the fixed 512×512 JPEG output (feature 004) | `disintegration/imaging` (unmaintained, wraps x/image), libvips bindings (cgo, large attack surface), dropping WebP (spec requires it) | Go project |
| `github.com/getkin/kin-openapi` | v0.149.0 | OpenAPI 3 parsing and request validation for the console API | manual validation per handler (drifts from the contract) | Active |

Test-only: stdlib `testing` + fuzzing; `testcontainers-go` (TimescaleDB, Valkey, OpenFGA, mailpit) under the `integration` tag.

Console (pinned by `package-lock.json`, `npm audit --audit-level=high` in CI): vue 3.5, vuetify 4.2, vue-router 5, pinia 4, vite 8, typescript 5.9 (7 conflicts with vue-tsc/openapi-typescript peers), vitest 5, @playwright/test 1.63 + @axe-core/playwright, openapi-typescript, qrcode (TOTP enrolment QR), @mdi/font 7 (Material Design Icons webfont for the `mdi-*` icon names Vuetify uses; bundled by Vite so it is served from the same origin under the `font-src 'self'` CSP).

## Advisories

- `golang.org/x/crypto@v0.57.0`: `govulncheck` reports GO-2026-5932 in a
  package this module does not call ("modules you require, but your code doesn't
  appear to call"); no fix released at the time of writing. Re-run
  `make vuln` and upgrade as soon as a fixed version exists. The service uses
  only `argon2` from this module.
