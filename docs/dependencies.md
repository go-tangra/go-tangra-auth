# Dependency Justification — services/auth (Constitution Principle VI)

| Dependency | Version | Purpose | Alternatives rejected | Maintenance |
|------------|---------|---------|------------------------|-------------|
| `github.com/go-tangra/go-tangra/v4` | local (`replace ../..`) | mTLS transports, identity, service policy, audit, observability, edge listener | — | this repository |
| `github.com/openfga/go-sdk` | v0.8.2 | OpenFGA client (Check/BatchCheck/Write/model bootstrap) | raw gRPC to OpenFGA (re-implements the SDK) | Active (CNCF sandbox) |
| `github.com/jackc/pgx/v5` | v5.11.0 | PostgreSQL/TimescaleDB driver and pool | database/sql + lib/pq (no COPY, weaker types) | Active |
| `github.com/pressly/goose/v3` | v3.28.0 | Embedded SQL migrations with advisory lock | golang-migrate (heavier) | Active |
| `github.com/valkey-io/valkey-go` | v1.0.78 | Valkey client (RESP3) | go-redis (larger surface) | Active |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | JWT with pinned EdDSA | jwx (larger), hand-rolled (prohibited) | Active |
| `golang.org/x/crypto` | v0.57.0 | argon2id | none (constitution-approved) | Go project |
| `github.com/pquerna/otp` | v1.5.0 | TOTP (RFC 6238) | hand-rolled | Active |
| `golang.org/x/image` | v0.46.0 | avatar pipeline: WebP decoding (`webp`) and CatmullRom resampling (`draw`) for the fixed 512×512 JPEG output (feature 004) | `disintegration/imaging` (unmaintained, wraps x/image), libvips bindings (cgo, large attack surface), dropping WebP (spec requires it) | Go project |
| `github.com/getkin/kin-openapi` | v0.149.0 | OpenAPI 3 parsing and request validation for the console API | manual validation per handler (drifts from the contract) | Active |
| `github.com/go-ldap/ldap/v3` | v3.4.14 | LDAPv3 client for the filtered directory import (feature 016): `DialURL` with a policy `net.Dialer` + caller `tls.Config`, `StartTLS`, `SimpleBind`, bounded `Search`, RFC 4515 `CompileFilter`, `ParseDN`, `EscapeFilter`. NTLM/GSSAPI/unauthenticated binds are never used | hand-written LDAPv3/BER client (large, security-critical parser); `nmcclain/ldap` (unmaintained fork); shelling out to `ldapsearch` (process spawning, no typed errors) | Active (MIT; used by Grafana, Gitea, Dex, Authelia) |
| `github.com/go-tangra/go-tangra-notification/sdk/v4` | v4.2.0 | notification client (`pkg/notifyclient`, `notification.v1` protos): the outbox sends by template key (feature 017) | own copy of the protos (drifts from notification); SMTP in auth (a second relay, credentials in every service) | go-tangra (grpc + protobuf only) |
| `github.com/go-asn1-ber/asn1-ber` | v1.5.8 (indirect) | BER encoding/decoding under go-ldap; the packet size cap is set from `internal/ldapdir` | — (comes with go-ldap) | Active (same maintainers as go-ldap, MIT) |
| `github.com/Azure/go-ntlmssp` | v0.1.1 (indirect) | Pulled in by go-ldap's NTLM bind; linked but never called (only `SimpleBind` is used) | — (comes with go-ldap) | Maintained by Microsoft/Azure (MIT) |

Test-only: stdlib `testing` + fuzzing; `testcontainers-go` (TimescaleDB, Valkey, OpenFGA) under the `integration` tag; notification is an in-process fake (`internal/email/notifytest`).

Console (pinned by `package-lock.json`, `npm audit --audit-level=high` in CI): vue 3.5, vuetify 4.2, vue-router 5, pinia 4, vite 8, typescript 5.9 (7 conflicts with vue-tsc/openapi-typescript peers), vitest 5, @playwright/test 1.63 + @axe-core/playwright, openapi-typescript, qrcode (TOTP enrolment QR), @mdi/font 7 (Material Design Icons webfont for the `mdi-*` icon names Vuetify uses; bundled by Vite so it is served from the same origin under the `font-src 'self'` CSP).

## Advisories

- `github.com/go-ldap/ldap/v3@v3.4.14` (+ `asn1-ber@v1.5.8`, `go-ntlmssp@v0.1.1`):
  baseline `govulncheck` on 2026-09-24 found no vulnerabilities in these modules.
  Pinned by `go.sum`; re-run `make vuln` and review the upstream changelog on
  every bump. `go.sum` also lists go-ldap's test-only modules (`jcmturner/gokrb5`,
  `alexbrainman/sspi`); they are not linked into the binary.

- `golang.org/x/crypto@v0.57.0`: `govulncheck` reports GO-2026-5932 in a
  package this module does not call ("modules you require, but your code doesn't
  appear to call"); no fix released at the time of writing. Re-run
  `make vuln` and upgrade as soon as a fixed version exists. The service uses
  only `argon2` from this module.
