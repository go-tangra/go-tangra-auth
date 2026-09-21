# Quickstart — User Groups & User Profiles

Validates the feature end-to-end on the platform stack from feature 003 (auth
in gateway mode + gateway + hello module). Contract details are in
[contracts/](contracts/), entities in [data-model.md](data-model.md).

## Prerequisites

Go 1.26, Node 22, Docker with compose; test CA from `make testca`. A running
stack as in `specs/003-application-gateway/quickstart.md` §1–§2 **after**
applying the new auth migration (`./bin/authsvc migrate -config
deploy/gateway-mode.yaml` or start without `-no-migrate`) and re-registering
the console permissions (automatic on start).

## 1. Gates

```bash
make -C services/auth lint cover fuzz        # 100 % on internal/authz, internal/user (profile, avatar)
make -C services/gateway lint test
(cd services/auth/console && npm run lint && npm run test:unit)
(cd services/gateway/shell && npm run lint && npm run test:unit)
go test ./services/auth/tests/contract/...   # OpenAPI ↔ routes, proto, FGA model
```

Expected: all green; coverage gate passes; `govulncheck` clean with the new
`golang.org/x/image` module.

## 2. Groups grant access (US1, SC-002, SC-003, SC-008)

```bash
go test -tags integration ./services/auth/tests/integration -run 'TestGroups' -v
```

Covers: create group → assign role → add member → `Authorization/Check`
allowed within 1 s → remove member → refused; direct + group union with
sources; escalation refusals (non-admin, non-owner granting `admin` via a
group, cross-tenant member); delete with member-count confirmation; one audit
event per change; 20-group user decision latency within 10 % of direct-only
(benchmark printed).

Manual, through the shell (https://localhost:8443, operator account):
**Groups → New** "Finance", roles: `hello-user`, add a second user. Sign in as
that user in another browser: the **Hello** nav entry and the "Say hello"
button are enabled without a re-login; remove the membership: on the next
navigation they are gone (SC-002).

## 3. Own profile (US2, SC-004, SC-005, SC-007)

```bash
go test -tags integration ./services/auth/tests/integration -run 'TestProfile|TestAvatar|TestRedaction' -v
go test ./services/auth/tests/fuzz -run Fuzz -fuzz FuzzAvatar -fuzztime 60s
```

Covers: names/phone validation and normalisation; avatar corpus (valid
PNG/JPEG/WebP; HTML named `.png`; 5000×5000 bomb; truncated JPEG; EXIF-laden
JPEG → stored bytes carry no EXIF); avatar served only to same-tenant sessions,
cross-tenant → 404; content-hash URL changes on replace; phone absent from
`/api/v1/session`, `Exchange`, tokens, `/gateway/v1/me`, logs and audit (scan).

Manual: **Account → Profile**: set names, phone, upload a photo → the shell
header shows the name and picture on the next page load (the auth remote
dispatches `freya:session-changed`, the gateway dropped its cached identity via
`X-Freya-Identity-Refresh`).

## 4. Admin edits and effective roles (US3)

Manual: **Users → user → Profile**: change the last name and remove the avatar;
**Effective roles** shows each role with "direct" or "via Finance". As the
edited user, reload within 60 s: the new name appears (SC-004).

```bash
go test -tags integration ./services/auth/tests/integration -run 'TestAdminProfile|TestEffectiveRoles' -v
```

## 5. Invitation into groups (US4)

Manual: **Users → Invite** with first/last name and group "Finance" → accept
from Mailpit (http://localhost:8025) → the new user's profile shows the names
and **Groups** lists "Finance"; delete the group before acceptance in a second
run → acceptance succeeds and the audit event lists `skipped_groups`.

## 6. Platform surfaces (gateway & shell)

```bash
go test -tags integration ./services/gateway/tests/integration -run 'TestIdentityProfile|TestIdentityRefreshRelay' -v
(cd services/gateway/shell && E2E_OPERATOR_EMAIL=... E2E_OPERATOR_PASSWORD=... npx playwright test profile)
```

Expected: `/gateway/v1/me` carries `display_name`, `avatar_url` and effective
roles; a forged `X-Freya-Identity-Refresh` from the browser is ignored; the
Playwright spec edits the profile in the auth remote and asserts the shell
header (`me-name`, `me-avatar`) updates without a sign-out, and axe reports no
critical issues on the new screens.

## 7. Upgrade safety (SC-009)

Start the new auth binary against a database populated by feature 002/003
integration fixtures: existing users keep `display_name`, sessions and tokens
stay valid, `Roles` in existing sessions are unchanged until the tenant's
policy version moves. `go test -tags integration ./services/auth/tests/integration -run TestUpgrade -v`.
