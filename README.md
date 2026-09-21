# services/auth — tenant authentication & authorization

A multi-tenant authentication and authorization service built on the Freya
framework (`github.com/go-freya/freya`). It signs users in through a Vue/Vuetify
console, issues short-lived EdDSA tokens that platform services verify offline,
answers fine-grained authorization decisions through OpenFGA and gives tenant
administrators and platform operators an audited management surface.

Design: `specs/002-tenant-auth-service/` (spec, plan, data model, contracts).
Security model: [`docs/security-model.md`](docs/security-model.md).
Operations: [`docs/operations.md`](docs/operations.md).

Feature 004 adds tenant **groups** (roles assignable to groups; effective roles
are the union of direct and group roles, enforced through the OpenFGA model) and
user **profiles** (first name, last name, phone, avatar) exposed to the platform
through the session identity and the gateway's `/gateway/v1/me`. See
`docs/security-model.md`. Feature 005 adds member-level `GET /api/v1/users?q=`
and `GET /api/v1/roles` for subject pickers, and `builtin_grants` on
`RegisterPermissions` so modules seed their own role grants.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/authsvc` | service binary (`run`, `bootstrap`) |
| `internal/app` | wiring: config → Freya → stores → services → HTTP/gRPC |
| `internal/{user,session,token,password,mfa,invite,tenant,authz,oauth}` | security logic (unit-tested to 100 % where the constitution requires it) |
| `internal/*/…db` and `internal/store` | SQL bindings (TimescaleDB, RLS); covered by the tagged integration suite |
| `internal/httpapi`, `internal/grpcapi` | browser API (OpenAPI-validated) and `auth.v1` service API |
| `pkg/authclient` | verifier library for downstream services (offline JWT + revocation feed) |
| `console` | Vue 3 + Vuetify + TypeScript console (served at `/console/`) |
| `api/openapi`, `api/proto` | contracts (`console.yaml`, `auth.v1`, `demo.v1`) |
| `deploy` | compose stack, dev config, policies |
| `tests/{contract,fuzz,integration}` | contract, fuzz and Docker-backed integration suites |

## Run it

```bash
make -C services/auth compose-up            # TimescaleDB, Valkey, OpenFGA, mailpit
go run ./cmd/authsvc bootstrap -config deploy/dev.yaml -operator-email ops@example.org
go run ./cmd/authsvc -config deploy/dev.yaml
(cd console && npm ci && npm run build)      # then rebuild the service with -tags console
```

Quickstart with expected results: `specs/002-tenant-auth-service/quickstart.md`.

## Gates

```bash
make -C services/auth lint cover fuzz        # vet, golangci-lint, unit coverage gate, fuzz smoke
make -C services/auth test-integration       # -tags integration (needs Docker)
make -C services/auth redaction-scan         # secrets never reach logs/audit/outbox/errors
(cd services/auth/console && npm run lint && npm run test:unit && npm run test:e2e)
```

The unit coverage gate requires ≥ 80 % overall and 100 % for
`internal/{token,session,password,mfa,tenantctx}`; generated code, SQL
bindings and wiring are excluded from the unit gate and exercised by the
integration suite instead.

## Moving to its own repository

The service is a standalone Go module (`services/auth/go.mod`) with a `replace`
directive pointing at the framework. To split it out:

1. Copy `services/auth` to the new repository root; keep `go.mod`'s module path
   or rename it and update the import paths (`internal/...`, `pkg/authclient`,
   `api/proto/...`).
2. Replace `replace github.com/go-freya/freya => ../..` with a tagged
   `require github.com/go-freya/freya vX.Y.Z`.
3. Move `.github/workflows/ci.yml`'s `auth-service*` jobs into the new
   repository's workflow; they only reference paths inside the service.
4. Regenerate the console API types (`npm run gen:api`) and protobuf code
   (`buf generate`) — both read files inside the service.
5. Downstream services import `pkg/authclient` from the new module path.

Nothing in the framework imports the service; nothing in the service reaches
outside its directory except the `replace` directive.
