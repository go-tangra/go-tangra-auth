# go-tangra-auth

Tenant authentication and authorization service for the
[go-tangra v4 platform](https://github.com/go-tangra/go-tangra).

It signs users in through its own console, issues short-lived EdDSA tokens that
platform services verify offline, answers fine-grained authorization decisions
through OpenFGA, and gives tenant administrators and platform operators an
audited management surface: tenants, users, invitations, MFA and recovery,
roles, groups, user profiles and LDAP directory import.

Security model: [`docs/security-model.md`](docs/security-model.md).
Operations: [`docs/operations.md`](docs/operations.md).
Design history: `specs/002-tenant-auth-service`, `specs/004-groups-user-profiles`,
`specs/016-auth-ldap-import`.

## Place in the platform

```
go-tangra/go-tangra          platform module + @go-tangra/ui kit
        |
go-tangra-auth  <---->  go-tangra-portal (gateway)  <---->  modules (lcm, warden, ...)
```

- Built on `github.com/go-tangra/go-tangra/v4` (mTLS transports, identity,
  service policy, audit, observability).
- The portal gateway fronts the console and the browser API. Modules register
  their permissions with auth and verify tokens with the auth SDK.
- Registers with the gateway through the portal SDK
  (`github.com/go-tangra/go-tangra-portal/sdk/v4`).

## Modules in this repository

| Module | Path | Consumers |
|---|---|---|
| `github.com/go-tangra/go-tangra-auth/v4` | `/` | the service (`cmd/authsvc`) and `pkg/authmanifest` |
| `github.com/go-tangra/go-tangra-auth/sdk/v4` | `sdk/` | other services: the `auth.v1` protobuf API and `pkg/authclient` (offline JWT verification and revocation feed) |

The service builds against the in-repo SDK through
`replace github.com/go-tangra/go-tangra-auth/sdk/v4 => ./sdk`. Consumers use the
SDK's published `sdk/vX.Y.Z` tag.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/authsvc` | service binary (serve, `bootstrap`, `version`) |
| `internal/app` | wiring: config, platform, stores, services, HTTP/gRPC |
| `internal/...` | sessions, tokens, passwords, MFA, invitations, tenants, authz, OAuth, directory import, and their SQL bindings |
| `console` | Vue 3 + FlyonUI console on `@go-tangra/ui` (served at `/console/`, plus a federated remote) |
| `api/openapi`, `sdk/api/proto` | contracts (`console.yaml`, `auth.v1`) |
| `deploy` | compose stack, dev configuration, policies |
| `tests/{contract,fuzz,integration}` | contract, fuzz and Docker-backed integration suites |

## Build and test

You need Go 1.26, Node 22, Docker (for integration tests and the image), and a
GitHub token with `read:packages` to install `@go-tangra/ui` from GitHub Packages.

```bash
go build ./... && go vet ./... && go test -race ./...
(cd sdk && go vet ./... && go test -race ./...)
make test-integration                     # -tags integration, needs Docker
make lint cover fuzz redaction-scan vuln

cd console
export NODE_AUTH_TOKEN=$(gh auth token)   # console/.npmrc only references this variable
npm ci && npm run lint && npm run test:unit && npm run build && npm run build:remote
```

The unit coverage gate requires at least 80 % overall and 100 % for the
security-critical packages. Generated code, SQL bindings and wiring are covered
by the integration suite instead.

## Run locally

```bash
make compose-up                           # TimescaleDB, Valkey, OpenFGA
go run ./cmd/authsvc bootstrap -config deploy/dev.yaml -operator-email ops@example.org
go run -tags "console remote" ./cmd/authsvc -config deploy/dev.yaml   # after the console build
```

## Container image

The image is `ghcr.io/go-tangra/go-tangra-auth`, built by `.github/workflows/ci.yaml`.

```bash
docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN \
  --build-arg APP_VERSION=4.0.0 -t go-tangra-auth:dev .
docker run --rm go-tangra-auth:dev version
```

The image runs `authsvc -config deploy/dev.yaml` as user `app` (uid 10001).
Production deployments mount their own configuration.

## Versioning

- Service releases are tagged `vX.Y.Z`. CI publishes the image as `X.Y.Z`,
  `X.Y`, `X` and `sha-<short>`. There is no `latest` tag.
- The SDK is released separately with `sdk/vX.Y.Z` tags. These tags never build an image.
- v4.0.0 is the first release of this repository. It matches the go-tangra v4
  platform major version.
