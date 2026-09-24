# Tasks: LDAP User Import for the Auth Service

**Feature**: 016-auth-ldap-import | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

Organized by phase; user-story phases are independently testable. Tests are
MANDATORY and precede implementation (Constitution IV). `[P]` = parallelizable
(different files, no dependency on an incomplete task). This is a feature
**inside the existing module** `github.com/go-freya/freya/services/auth`: follow
its conventions (`<domain>` + `<domain>db` packages, `memstore`, goose
migrations with `tenant_isolation` RLS + `auth_app` grants, handler files per
area in `internal/httpapi`, closed error vocabulary, audit via
`internal/audit`, console views under `console/src/views/admin` with
`@freya/ui` drawers). Design references: research.md D1–D18,
data-model.md, contracts/ldap-import-api.md, quickstart.md. New security-critical
package `internal/ldapdir` joins the 100 % coverage set.

## Phase 1: Setup (Shared Infrastructure)

- [ ] T001 Add `github.com/go-ldap/ldap/v3` (latest v3.4.x) to `services/auth/go.mod`, run `go mod tidy` to refresh `services/auth/go.sum`, run `make vuln` for a baseline, and add the dependency row (purpose, alternatives, maintenance; transitive go-asn1-ber and go-ntlmssp) to `services/auth/docs/dependencies.md` (research D2, supply-chain note).
- [ ] T002 [P] Create package skeletons with `doc.go` (security notes per package): `services/auth/internal/ldapdir/doc.go`, `services/auth/internal/ldapdir/ldapfake/doc.go`, `services/auth/internal/directory/doc.go`, `services/auth/internal/directory/directorydb/doc.go`.
- [ ] T003 [P] Repo-owned OpenLDAP test image in `services/auth/tests/integration/testdata/openldap/`: `Dockerfile` (alpine pinned by digest + openldap, openldap-back-mdb, overlays; verify at implementation that osixia/bitnami are indeed unsuitable, research D17), `slapd.ldif` (mdb, ldaps 636 + StartTLS 389, TLS cert paths), `people.ldif` (dc=example,dc=test: Engineering ×5 with mail, Sales ×3, one without mail, two sharing a mail, alias to ou=Secret, a referral object, one 1 MiB description, service account cn=reader), `README.md`.
- [ ] T004 [P] Fuzz/table corpora under `services/auth/tests/fuzz/testdata/ldap/`: filters (valid RFC 4515, invalid, injection strings `*)(|(objectClass=*)`, `x)(|(uid=*))(`, NUL, 6 KiB, deep nesting), DNs (escaped commas, multi-valued RDNs, case variants), URLs (schemes, userinfo, IPv6 literals, ports), raw objectGUID byte strings.
- [ ] T005 [P] Add `internal/ldapdir` to `SECURITY_PKGS` in `services/auth/scripts/coverage-gate.sh` and the new packages to `services/auth/scripts/redaction-scan.sh`.

## Phase 2: Foundational (Blocking Prerequisites)

- [ ] T006 Tests first for the directory config section in `services/auth/internal/config/config_test.go`: defaults (enabled, ports 389/636/3268/3269, dial 5 s, max size 1000, max time 60 s, rate 30/min, 10 connections), CIDR parse errors, port range, limit bounds, `allow_plaintext` refused when `env: production`, `Warnings()` lists allow_plaintext and allow_cidrs.
- [ ] T007 Implement the typed `Directory` section (`enabled`, `allow_plaintext`, `targets.{deny_cidrs,allow_cidrs,allowed_ports}`, `dial_timeout`, `max_size_limit`, `max_time_limit`, `rate_per_minute`, `max_connections_per_tenant`) with Default/Validate/Warnings in `services/auth/internal/config/config.go` (research D15).
- [ ] T008 Tests first for migration 0008 in `services/auth/internal/store/migrate_test.go` (`//go:build integration`): `users.status` accepts `imported` and still rejects unknown values, RLS enabled+forced on `directory_connections` and `user_directory_links` (tenant B context sees no tenant A rows), unique `(tenant_id, lower(name))`, unique `(tenant_id, connection_id, directory_uid)`, `ON DELETE SET NULL` on connection delete, `ON DELETE CASCADE` on user delete, `auth_app` grants.
- [ ] T009 Write `services/auth/internal/store/migrations/0008_ldap_import.sql` per data-model.md (tables, CHECKs, indexes incl. `users_imported_idx`, RLS loop, grants, replaced status CHECK, documented destructive Down).
- [ ] T010 Store models and SQL in `services/auth/internal/store/directory.go` (DirectoryConnection, DirectoryLink, ImportedProfile; insert/get/list/count/update/set-test/delete connection; UsersByEmails; LinksByUIDs; UpsertLink; UpdateImportedUser `WHERE status='imported'`; DeleteImportedUser `WHERE status='imported'`) and extend `ListUsers` in `services/auth/internal/store/repos.go` to return the link (origin) and pending invitation id.
- [ ] T011 [P] In-memory implementation in `services/auth/internal/memstore/directory.go` (same uniqueness, SET NULL/CASCADE and status-guard semantics as SQL; FailNext injection) + wiring in `services/auth/internal/memstore/memstore.go`.
- [ ] T012 [P] Audit vocabulary: add `directory_connection_created|updated|deleted`, `directory_connection_tested`, `directory_searched`, `directory_imported`, `imported_user_deleted` to `services/auth/internal/audit/audit.go` + registration test in `services/auth/internal/audit/audit_test.go`.
- [ ] T013 [P] Tests first — imported ≡ non-existent (SR-006, SC-002): `services/auth/internal/user/signin_test.go` (imported vs unknown e-mail: same `invalid_credentials`, audit reason `unknown_account`, no lockout counter after 10 attempts, never `locked`, dummy verify executed), `services/auth/internal/password/recovery_test.go` (imported address: identical ack, same pad, no outbox row, no recovery request), `services/auth/internal/invite/invite_test.go` accept case (an `imported` row is never activated by `Accept`).
- [ ] T014 Make sign-in treat `imported` as unknown (`known` only when `u.Status != "imported"`) in `services/auth/internal/user/signin.go` (research D10).
- [ ] T015 [P] Tests first — status guards in `services/auth/internal/user/admin_test.go` (Deactivate and Reactivate on an imported user → `ErrInvalidState`, status unchanged, no sessions touched) and `services/auth/internal/store/groups_test.go` (`AddGroupMembers` never adds an imported user).
- [ ] T016 Implement `ErrInvalidState` refusals in `services/auth/internal/user/admin.go`, the `u.status <> 'imported'` filter in `services/auth/internal/store/groups.go`, the `invalid_state` 409 mapping in `services/auth/internal/httpapi/admin.go` (`adminError`) and the imported-target refusal in `setUserRoles`, with a handler test in `services/auth/internal/httpapi/admin_test.go`.
- [ ] T017 [P] Tests first for the target policy in `services/auth/internal/ldapdir/policy_test.go`: always-deny set (127/8, ::1, 169.254.169.254, fe80::/10, 0.0.0.0, ::, multicast, IPv4-mapped loopback), deny_cidrs, allow_cidrs overriding deny_cidrs but never the always-deny set, allowed_ports, `CheckURL` (scheme ldap|ldaps, host required, no userinfo/path/query/fragment, default ports, IPv6 literal, literal IP pre-check), `Control` refusing on the resolved address.
- [ ] T018 Implement `services/auth/internal/ldapdir/policy.go` (TargetPolicy, CheckURL, net.Dialer Control) — research D5.
- [ ] T019 [P] Tests first for TLS config in `services/auth/internal/ldapdir/tlsconf_test.go`: CA PEM > 64 KiB / no certificate / garbage → `ErrInvalidCA`; system roots when empty; `MinVersion` TLS 1.3 by default, TLS 1.2 only with `allow_tls12` and only AEAD ECDHE suites; `ServerName` from URL host; `InsecureSkipVerify` always false.
- [ ] T020 Implement `services/auth/internal/ldapdir/tlsconf.go` (research D3).
- [ ] T021 [P] Tests first for the real client and error mapping in `services/auth/internal/ldapdir/client_test.go` + `services/auth/internal/ldapdir/errors_test.go`: dial via policy dialer (refused target → `ErrTargetRefused`, closed port → `ErrUnreachable`, dial timeout → `ErrTimeout`), local TLS listener with an untrusted cert → `ErrTLS`, StartTLS failure never falls back to plaintext, LDAP result codes → closed errors (49 → invalid_credentials, 32 → base_not_found, 4/3 → truncated/timeout, others → `ErrDirectory` carrying only the code), error strings never contain server diagnostic text or the password; BER packet cap set.
- [ ] T022 Implement `services/auth/internal/ldapdir/client.go` (Directory/Session over go-ldap: DialURL + DialWithDialer + DialWithTLSConfig, StartTLS, SimpleBind with zeroed password buffer, BaseExists, Search with SizeLimit+1/TimeLimit/NeverDerefAliases/attribute list, referral counting, TLSState) and `services/auth/internal/ldapdir/errors.go` (contracts §C).
- [ ] T023 [P] In-memory directory `services/auth/internal/ldapdir/ldapfake/fake.go` + `services/auth/internal/ldapdir/ldapfake/fake_test.go` (entries by DN, base DN checks, alias entries honouring the deref flag, referrals, size/time-limit behaviour, bind credentials, per-call error injection, records every Query and Bind).

## Phase 3: User Story 1 — Connect a directory (Priority: P1) 🎯 MVP

**Goal**: tenant admins create, view, edit, test and delete TLS-protected LDAP connections with a sealed, write-only bind password.
**Independent test**: add a connection, run Test (success and each failing step), save, confirm the password is never returned; edit without password keeps it; delete keeps imported users (quickstart Scenario 1).

- [ ] T024 [P] [US1] Tests first for connection CRUD in `services/auth/internal/directory/directory_test.go`: create seals the password with AD `ldap-bind:<tenant>:<id>` (ciphertext copied to another connection or tenant fails to open), views never contain the password (`bind_password_set` only), update without password keeps the ciphertext, empty password refused, plaintext refused in production and allowed only with the dev opt-out, invalid URL/port/CA/bind DN/base DN/base filter refused, kind presets fill the mapping, duplicate name → `duplicate`, per-tenant cap → `limit_reached`, remove keeps imported users (link `connection_id` NULL, `connection_name` kept), audit events with no secret in details, cross-tenant id → not found + `cross_tenant_refused`.
- [ ] T025 [P] [US1] Tests first for connection testing in `services/auth/internal/directory/test_test.go` (ldapfake): step reporting connect/tls/bind/search_base with the closed reasons, success returns TLS version, `last_test` persisted for saved connections, unsaved test reusing the stored password via `connection_id` only within the tenant, per-tenant rate limit → `rate_limited`, `directory_connection_tested` audit, results and errors never contain the password or server text.
- [ ] T026 [P] [US1] Tests first for the HTTP surface in `services/auth/internal/httpapi/directory_test.go`: `RequirePermission` (owner/admin allowed, custom role with `directory:manage` allowed through the authz fake, member 403, unauthenticated 401), CSRF required on mutations, list/create/get/update/remove/test routes and status codes per contracts §A, response bodies have no password field, error reason mapping, cross-tenant 404, feature disabled (`directory.enabled: false`) → 404.
- [ ] T027 [P] [US1] Contract and manifest tests first: `services/auth/tests/contract/openapi_test.go` (directory connection routes declared, csrf on mutations, `bind_password` writeOnly in input and absent from `DirectoryConnection`, `additionalProperties: false`) and `services/auth/pkg/authmanifest/manifest_test.go` (`directory:manage` permission, grants to owner/admin/operator only, ability, nav entry, version 1.2.0).
- [ ] T028 [US1] Add the connection routes and schemas (`DirectoryConnection`, `DirectoryConnectionInput`, `TestResult`) to `services/auth/api/openapi/console.yaml` (info.version 1.2.0) and regenerate `services/auth/console/src/api/schema.d.ts`.
- [ ] T029 [US1] Add the `directory:manage` permission, grants, ability, nav entry and version bump in `services/auth/pkg/authmanifest/manifest.go`.
- [ ] T030 [US1] Implement connection CRUD + sealing + validation in `services/auth/internal/directory/directory.go` (crypto.Envelope, policy.CheckURL, ldapdir filter/DN validation of base filter and bind/base DNs, cap, audit).
- [ ] T031 [US1] Implement `Test` (open → TLS → bind → BaseExists, step/outcome, last_test, rate limit via `cache.Count`) in `services/auth/internal/directory/test.go`.
- [ ] T032 [US1] Implement the pgx store in `services/auth/internal/directory/directorydb/db.go` (Atomic under `store.Scope{TenantID}`, `ConnectionAnyTenant` under system scope for the cross-tenant audit only).
- [ ] T033 [US1] Implement `RequirePermission` and the connection handlers in `services/auth/internal/httpapi/directory.go` with `RegisterDirectory(DirectoryDeps)`.
- [ ] T034 [US1] Wire the target policy, TLS/client, BER cap, directory service and routes (skipped when `directory.enabled` is false) in `services/auth/internal/app/app.go`.
- [ ] T035 [P] [US1] Console unit tests first in `services/auth/console/tests/unit/directories.spec.ts`: list columns and last-test chip, drawer kind presets, password field write-only ("stored — leave blank to keep"), Test shows failing step/reason, delete confirm text, zod schema errors.
- [ ] T036 [US1] Console: `services/auth/console/src/schemas/directory.ts`, `services/auth/console/src/views/admin/Directories.vue`, `services/auth/console/src/views/admin/DirectoryDrawer.vue`, routes in `services/auth/console/src/router/routes.ts` and `services/auth/console/src/remote/routes.ts`, nav in `services/auth/console/src/remote/nav.ts`.

## Phase 4: User Story 2 — Search with a filter and import selected people (Priority: P1)

**Goal**: filtered, base-scoped, limited directory search with a preview of platform status, and idempotent import of selected entries as inactive `imported` users with no e-mail.
**Independent test**: run a filtered search, see only matching entries, import a selection, see them listed as `imported` with origin; re-import creates no duplicates; none can sign in and no e-mail was sent (quickstart Scenario 2).

- [ ] T037 [P] [US2] Tests first for filters in `services/auth/internal/ldapdir/filter_test.go`: valid/invalid RFC 4515 (parser position message, no network), empty → `(objectClass=*)`, length/depth/component caps, invalid attribute descriptions, `:dn:` extensible match refused, canonical output, `Combine` always yields a root AND whose first child equals the base filter for every injection string in the corpus.
- [ ] T038 [P] [US2] Tests first for DN scoping in `services/auth/internal/ldapdir/dn_test.go`: `ScopeBase` equal/descendant/outside/sibling-suffix trick (`ou=Eng,dc=example,dc=test` vs `dc=evilexample,dc=test`)/case/escaped commas/multi-valued RDN/invalid DN, `WithinBase` for returned entry DNs.
- [ ] T039 [P] [US2] Tests first for attribute mapping in `services/auth/internal/ldapdir/mapping_test.go`: defaults per kind, AD objectGUID 16 bytes → canonical GUID (little-endian groups), wrong length → invalid, entryUUID string, multi-valued uid → `multi_valued_uid`, value caps → `value_too_long`, missing/invalid mail, e-mail normalisation identical to invitations, names through `user.ValidateName`, display-name fallback.
- [ ] T040 [P] [US2] Fuzz targets in `services/auth/tests/fuzz/ldap_fuzz_test.go` seeded from `services/auth/tests/fuzz/testdata/ldap/`: `FuzzCompileUserFilter` (never panics; accepted filters re-compile to the same canonical form), `FuzzCombine` (root AND with base first child), `FuzzScopeBase`, `FuzzCheckURL`, `FuzzDecodeEntry` (GUID/values/emails never panic, outputs within caps).
- [ ] T041 [P] [US2] Tests first for search in `services/auth/internal/directory/search_test.go` (ldapfake): recorded query has effective filter `(&base user)`, connection base or narrowed base, `NeverDerefAliases`, mapped attribute list only, SizeLimit = limit+1, TimeLimit; invalid filter/base → zero directory calls; alias target and out-of-base entries dropped and counted; referrals ignored; truncation flag on size/time limit; timeout → `timeout`; preview statuses new/existing_user/imported/invalid with user ids; `directory_searched` audit (canonical filter ≤ 1 KiB, count, truncated) with no entries; rate limit; cross-tenant connection → not found.
- [ ] T042 [P] [US2] Tests first for import in `services/auth/internal/directory/import_test.go` (ldapfake + memstore): each uid re-fetched with `(&base (<uid_attr>=<escaped>))` under the base (an injected uid like `*` matches nothing), uid not in the directory → `not_found_in_directory`, outcomes created/updated/skipped (`no_email`, `invalid_email`, `email_in_use`, `duplicate_email`, `already_active`, `value_too_long`)/failed, created users have status `imported`, no password, no MFA, link row with connection/uid/DN/timestamps; re-import idempotent (SC-004) and refreshes names/email only while `imported`; per-entry failure isolation; > 500 uids refused; **no outbox row ever written**; `directory_imported` audit with counts and user ids only.
- [ ] T043 [P] [US2] Tests first for the search/import HTTP routes and users list in `services/auth/internal/httpapi/directory_import_test.go`: 400 `invalid_filter`/`invalid_base`, 502/504 mapping, 200 partial ImportResult, gate `directory:manage`, CSRF; `GET /api/v1/admin/users?status=imported` returns imported users with `directory` origin and `invitation_id: null`; contract assertions for `SearchRequest`/`SearchResult`/`ImportRequest`/`ImportResult` and `User.status` enum in `services/auth/tests/contract/openapi_test.go`.
- [ ] T044 [US2] Implement `services/auth/internal/ldapdir/filter.go` (CompileUserFilter, Combine; research D6).
- [ ] T045 [US2] Implement `services/auth/internal/ldapdir/dn.go` (ScopeBase, WithinBase).
- [ ] T046 [US2] Implement `services/auth/internal/ldapdir/mapping.go` (DefaultMapping, Decode; research D7/D8).
- [ ] T047 [US2] Implement `Search` in `services/auth/internal/directory/search.go` (compile/combine/scope, session search, per-entry decode + WithinBase, preview status via UsersByEmails/LinksByUIDs, audit, rate limit).
- [ ] T048 [US2] Implement `Import` in `services/auth/internal/directory/import.go` and the corresponding store methods in `services/auth/internal/directory/directorydb/db.go` (re-fetch, per-entry transaction, outcomes, audit).
- [ ] T049 [US2] Add search/import routes, schemas and the `User` changes (`imported` status, `directory`, `invitation_id`) to `services/auth/api/openapi/console.yaml`, regenerate `services/auth/console/src/api/schema.d.ts`, and implement the handlers in `services/auth/internal/httpapi/directory.go`.
- [ ] T050 [US2] Extend `UserView` with `directory` origin and `invitation_id` in `services/auth/internal/user/admin.go` (and `services/auth/internal/user/userdb/db.go`) so the users list shows origin and supports `status=imported`.
- [ ] T051 [P] [US2] Console unit tests first in `services/auth/console/tests/unit/directory-import.spec.ts` and additions to `services/auth/console/tests/unit/admin.spec.ts`: filter input + parse error display, base/scope inputs, preview table statuses and selection (only `new`/`imported` selectable), truncation notice, import summary with skip reasons, users list `imported` chip, status filter option and origin tooltip.
- [ ] T052 [US2] Console: `services/auth/console/src/views/admin/DirectoryImport.vue`, route `/admin/directories/import` in `services/auth/console/src/router/routes.ts`, `imported` in `userStatuses` in `services/auth/console/src/api/vocab.ts`, imported chip/filter/origin in `services/auth/console/src/views/admin/Users.vue`, schemas in `services/auth/console/src/schemas/directory.ts`.

## Phase 5: User Story 3 — Activate imported users by sending invitations (Priority: P1)

**Goal**: holders of the invite capability activate imported users singly or in bulk with roles/groups under the escalation rules; each gets the standard invitation and becomes `invited`, then `active` on acceptance; imported users can be removed silently.
**Independent test**: activate one user → invitation e-mail, status `invited`; accept → `active` and can sign in; bulk-activate three → three invitations; admin granting `owner` refused; remove an imported user without e-mail (quickstart Scenario 3).

- [ ] T053 [P] [US3] Tests first for the shared escalation check in `services/auth/internal/authz/assign_test.go`: `MayAssign` — owner may grant anything; admin/custom-role actors cannot grant `owner`/`admin` or roles carrying permissions they lack (`ErrSelfEscalation`); group-granted roles checked through `Escalation.MayGrant`; `AssignRoles` behaviour unchanged.
- [ ] T054 [P] [US3] Tests first for activation in `services/auth/internal/invite/invite_test.go`: `Activate` moves `imported → invited` and inserts an invitation (names from the user row, roles, groups, 72 h) + an outbox `invite` row in the same transaction; non-imported → `invalid_state`; other-tenant id → not found + `cross_tenant_refused`; escalation refused before any invitation or outbox row; > 100 ids refused; one failing user does not affect the others; `invite_created` audit with reason `activation`; `CreateWith` for an imported e-mail converts to activation (no second user row, identical 202 path) and now runs the escalation check; `Accept` of an activation token → `active`, password set, roles bound, groups added, link row kept.
- [ ] T055 [P] [US3] Tests first for imported-user removal in `services/auth/internal/user/admin_test.go`: `RemoveImported` deletes only `imported` users (others → `ErrInvalidState`), link row cascades, no outbox row, `imported_user_deleted` audit, other-tenant id → not found.
- [ ] T056 [P] [US3] Tests first for the HTTP surface in `services/auth/internal/httpapi/activate_test.go`: `POST /api/v1/admin/users/activate` uses the invitation gate (owner/admin allowed; member and a custom role holding only `directory:manage` → 403), CSRF, per-user result items with `invitation_id`, 403 `self_escalation`; `POST /api/v1/admin/users/{id}/remove-imported` 204/409/404; `POST /api/v1/admin/invitations` with an imported e-mail still returns the identical `202 {queued:true}`; contract assertions for `ActivateRequest`/`ActivateResult` in `services/auth/tests/contract/openapi_test.go`.
- [ ] T057 [US3] Extract `MayAssign` from `AssignRoles` in `services/auth/internal/authz/assign.go` (AssignRoles calls it).
- [ ] T058 [US3] Implement `Activate`, the imported-conversion in `CreateWith` and the escalation dependency in `services/auth/internal/invite/invite.go`, plus `UserByID` in `services/auth/internal/invite/invitedb/db.go` and `services/auth/internal/memstore/memstore.go`; wire the dependency in `services/auth/internal/app/app.go`.
- [ ] T059 [US3] Implement `RemoveImported` in `services/auth/internal/user/admin.go` and `DeleteImportedUser` in `services/auth/internal/user/userdb/db.go`.
- [ ] T060 [US3] Add the activate and remove-imported routes/schemas to `services/auth/api/openapi/console.yaml`, regenerate `services/auth/console/src/api/schema.d.ts`, and implement the handlers (+ `invalid_state`/`self_escalation` mapping) in `services/auth/internal/httpapi/admin.go`.
- [ ] T061 [P] [US3] Console unit tests first in `services/auth/console/tests/unit/activate.spec.ts`: row actions for `imported` (Activate, Remove), drawer role/group pickers, bulk selection limited to imported rows, per-user failure summary, `self_escalation` message, resend available for `invited` users with an `invitation_id`.
- [ ] T062 [US3] Console: `services/auth/console/src/views/admin/ActivateDrawer.vue` (role/group pickers shared with `InviteDialog.vue`), multi-select + bulk Activate, Remove confirm and Resend in `services/auth/console/src/views/admin/Users.vue`, schema in `services/auth/console/src/schemas/directory.ts`.

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T063 [P] Redaction test `services/auth/internal/directory/redaction_test.go`: drive create/update/test/search/import/remove with a sentinel bind password and a directory that echoes it in diagnostic messages; assert it never appears in captured logs, audit rows, HTTP bodies or error strings (SR-002, SC-006); run `make redaction-scan`.
- [ ] T064 Integration test `services/auth/tests/integration/ldap_import_test.go` (`//go:build integration`; existing TimescaleDB/Valkey/OpenFGA/Mailpit harness + the T003 OpenLDAP container with a generated test CA): ldaps and StartTLS success, untrusted CA → `tls_failed`, wrong password → `invalid_credentials`, base filter + user filter, alias to ou=Secret not returned, referral not followed, size-limit truncation, 1 MiB attribute not transferred, import + re-import idempotent, activation → Mailpit invitation → accept → sign-in, imported sign-in/recovery indistinguishable from unknown, RLS isolation of both new tables across two tenants.
- [ ] T065 [P] SSRF integration test `services/auth/tests/integration/ldap_ssrf_test.go` (`//go:build integration`): real dialer refuses `127.0.0.1`, `[::1]`, `169.254.169.254`, a hostname resolving to loopback, the TimescaleDB container address and port 5432, and a deny_cidrs address unless in allow_cidrs; outcomes are the coarse `target_refused`/`unreachable` only.
- [ ] T066 [P] Console e2e `services/auth/console/tests/e2e/directory.spec.ts` (Playwright + axe, skips without `E2E_OPERATOR_PASSWORD` like the existing specs): create connection → test → import filtered selection → users list shows imported → activate → invitation in Mailpit.
- [ ] T067 [P] Dev stack: optional `openldap` service under compose profile `ldap` built from `services/auth/tests/integration/testdata/openldap/Dockerfile` in `deploy/stack/compose.yaml`, test CA in `deploy/stack/ldap/`, and the `directory` section (allow_cidrs for the stack LDAP only, `allow_plaintext: false`) in `deploy/stack/configs/auth.yaml`; note the profile in `deploy/stack/README.md`.
- [ ] T068 [P] Documentation: directory section (target policy and how to list platform CIDRs, TLS 1.3/1.2 opt-in, CA pinning, dev plaintext opt-out, limits, imported-status semantics, escalation change to plain invitations) in `services/auth/docs/security-model.md` and `services/auth/docs/operations.md`; `README.md` feature list in `services/auth/README.md`; entry in `CHANGELOG.md`.
- [ ] T069 Coverage + supply chain: `make -C services/auth cover` ≥ 80 % overall and 100 % on `internal/ldapdir` (plus the existing security packages) via `services/auth/scripts/coverage-gate.sh`; `make -C services/auth vuln` (govulncheck) and `make -C services/auth lint` (staticcheck, gosec) clean; `npm run lint` and vitest green in `services/auth/console`.
- [ ] T070 Security review (Constitution: Code Review) of `services/auth/internal/ldapdir`, `services/auth/internal/directory` and the changed sign-in/admin/invite paths against research STRIDE (filter injection, base/alias escape, TLS verification, SSRF dial-time policy, password sealing/redaction, enumeration via imported accounts, reactivate bypass, escalation at activation, cross-tenant); record findings and fixes in `services/auth/docs/security-model.md`.
- [ ] T071 Live smoke in the dev stack with the `ldap` profile: quickstart Scenarios 1–3 via the console or curl and the quickstart security checks (injection strings, plaintext refusal, SSRF targets, password absence in logs/audit, imported vs unknown sign-in/recovery, cross-tenant 404); record what could not be verified (e.g. browser flows without operator credentials) in `specs/016-auth-ldap-import/tasks.md`.

## Dependencies & sequencing

- Setup (T001–T005) → Foundational (T006–T023) block all stories. Within
  Foundational: T006 → T007; T008 → T009 → T010 → T011; T013 → T014; T015 →
  T016; T017 → T018; T019 → T020; T018 + T020 → T021 → T022; T023 after T022's
  interface is fixed (contracts §C lets it start in parallel).
- **US1** (connect) needs Foundational only. It is the MVP slice.
- **US2** (search + import) needs US1 (saved connection, directory service,
  handlers file, console Directories) — filters/DN/mapping (T037–T040, T044–T046)
  can start in parallel with US1 since they are pure `ldapdir` code.
- **US3** (activate) needs Foundational (status, store) and at least one way to
  create `imported` users — US2 for end-to-end, but its unit tests seed
  imported users directly in memstore, so T053–T059 can run in parallel with US2.
- Polish: T063 after US1–US2; T064 after US1–US3 and T003; T065 after T022;
  T066–T067 after US3; T069–T071 last.

## Parallel execution examples

- Phase 1: T002 ∥ T003 ∥ T004 ∥ T005 after T001.
- Phase 2: T006, T008, T012, T013, T015, T017, T019 in parallel; then T007,
  T009 → T010 → T011, T014, T016, T018, T020; then T021 → T022 ∥ T023.
- US1: T024 ∥ T025 ∥ T026 ∥ T027 ∥ T035, then T028 ∥ T029 ∥ T030 ∥ T032, then
  T031, T033 → T034, T036.
- US2: T037 ∥ T038 ∥ T039 ∥ T040 ∥ T041 ∥ T042 ∥ T043 ∥ T051, then T044 ∥ T045
  ∥ T046, then T047 → T048, T049 ∥ T050, T052.
- US3: T053 ∥ T054 ∥ T055 ∥ T056 ∥ T061, then T057 → T058, T059, T060, T062.
- Polish: T063 ∥ T065 ∥ T066 ∥ T067 ∥ T068, then T064, T069 → T070 → T071.

## Implementation strategy

MVP first: Setup + Foundational (including the imported-status safety net and
the `ldapdir` policy/TLS/client) + US1 → tenants can register and test a
directory securely. Then US2 (the requested filtered import), then US3
(activation completes the flow; its escalation hardening also changes plain
invitations — call it out in the CHANGELOG). All three stories are P1, so the
feature is not shippable to users until US3 lands, but each story is
demonstrable on its own. Finish with Polish (redaction, OpenLDAP and SSRF
integration suites, e2e, dev-stack profile, docs, coverage/vuln gates, security
review, live smoke).

## Summary

- **Total tasks**: 71 across 6 phases.
- **Per story**: US1 = 13 (T024–T036), US2 = 16 (T037–T052), US3 = 10 (T053–T062).
- **Setup / Foundational / Polish**: 5 + 18 + 9.
- **MVP scope**: Setup + Foundational + US1 (connect and test a directory);
  the full requested flow (filtered import + activation) is US1–US3.
- **Security-critical additions**: `internal/ldapdir` at 100 % coverage; fuzzed
  filter/DN/URL/mapping parsers; negative tests for injection, base/alias
  escape, TLS downgrade, SSRF, password leakage, enumeration, reactivate
  bypass, escalation and cross-tenant access.

## Live smoke record (T071, 2026-09-24)

Stack: `freya-stack` with `auth` rebuilt from this branch and the `ldap` profile
(`docker compose -p freya-stack -f deploy/stack/compose.yaml --profile ldap up -d --build --no-deps ldap-certs openldap auth`).
`auth` came up healthy and gateway-registered, with migration 0008 applied. No
operator credentials were available (only the pre-existing `admin@example.org`,
whose password and TOTP are unknown; `E2E_OPERATOR_PASSWORD` is unset), so no
admin session could be opened on the live stack. Each check below says whether
it was verified live on the stack, in the real-container integration suites
(T064/T065: real auth + TimescaleDB + the same OpenLDAP image), or only in the
unit/handler suites.

**Verified live on freya-stack**
- Infra: `openldap` healthy; the seed has `ou=Engineering`, `ou=Sales` and
  `ou=Secret`, plus `cn=reader`. From the `ldap` network, `172.31.250.2:636`
  negotiates TLS 1.3 and verifies against `deploy/stack/ldap/ca.pem`.
- Schema: `users_status_check` accepts `imported`; `users_imported_idx`
  exists; `directory_connections` and `user_directory_links` have RLS enabled
  and forced, with the `tenant_isolation` policy.
- Imported ≡ unknown (SR-006/SC-002), through the gateway with a passwordless
  `imported` fixture row (removed afterwards). 10 wrong sign-ins for the
  imported address and 10 for a random one gave identical results:
  `401 invalid_credentials`, ~0.31 s each (same pad), never `423`. All 20
  `signin_attempts` rows are `refused/unknown_account` with no user id, and all
  20 audit rows are `signin_failed/refused/unknown_account` with no actor. There
  was no `lockout` event, and Valkey has no per-user fail counter, only one
  `rl:signin_acct` key per address. `POST /api/v1/recovery` gave `202
  {"queued":true}` for both addresses, with no outbox row, no
  `recovery_requests` row, and audit `recovery_requested/refused/unknown_account`
  for both.
- Cross-tenant at the DB: as `auth_app` with a tenant-B `app.tenant_id`, a
  tenant-A connection, its link and the linked user are invisible (0/0/0). In
  the tenant-A context they are visible (1/1/1).
- Unauthenticated access: the directory and imported-user `GET`s return
  `401`. Unauthenticated `POST`s return `400 validation_failed` from the
  gateway CSRF guard, the same as every pre-existing admin `POST`.
- Plaintext: a dev config with `directory.allow_plaintext: true` starts with
  the warning `directory connections may use ldap:// without TLS`, and the
  allow-list override is logged (`allow_cidrs overrides deny_cidrs for:
  172.31.250.2/32`). The production refusal could not be isolated live,
  because a production config first fails on the stack's plaintext DB DSN. It
  is covered by `TestDirectoryPlaintextRefusedInProduction`.
- Password absence: after the run, the auth container log (440 lines) and
  `auth_audit_events` contain none of `reader-password`, the wrong passwords
  sent, or either smoke address.

**Verified only in the real-container integration suites**
All pass (`sg docker -c 'go test -tags integration -run TestLDAP ./tests/integration/'`):
- Scenario 1 (`TestLDAPDirectoryConnectTLS`): ldaps and StartTLS `ok`, wrong
  password → `invalid_credentials`, unknown CA → `tls_failed`. The
  `base_not_found` step is covered by unit tests only.
- Scenario 2 (`TestLDAPDirectorySearchImportActivate`): the alias to
  `ou=Secret` is not returned; `size_limit` gives `truncated`; import gives 4
  created with `no_email` and `duplicate_email` skipped, and no mail is sent;
  re-import gives `updated`. The one-vs-sub scope is covered by unit tests
  only.
- Scenario 3 steps 1–2 (activate → Mailpit → accept → sign in):
  `TestLDAPDirectorySearchImportActivate`.
- Injection strings with base filter `(departmentNumber=42)`:
  `TestLDAPDirectorySearchImportActivate`.
- Cross-tenant `404` over HTTP plus RLS: `TestLDAPDirectoryCrossTenantRLS`.
- SSRF targets (`127.0.0.1`, `[::1]`, `169.254.169.254`, localhost name,
  `timescaledb:5432`, a stack IP outside `allow_cidrs` → `target_refused`; no
  closed-vs-filtered distinction): `TestLDAPSSRFTargetPolicy`.

**Verified only in unit/handler suites (all green)**
`internal/directory`, `ldapdir`, `httpapi`, `invite`, `user`, `password`,
`authz`:
- `invalid_filter` / `invalid_base` / `base_not_found` / scope `one` vs `sub`
- `rate_limited`
- `self_escalation` / `forbidden`
- `remove-imported` on an active user → `409 invalid_state`
- deactivate→reactivate on an imported user → `409 invalid_state`
- the `cross_tenant_refused` audit row
- plain invite of an imported address → same row becomes `invited`
- resend

**Not verified**
- The whole console (browser) flow: Directories drawer, Import page, Users
  activation drawer, bulk activate. This needs operator or tenant-admin sign-in
  (password + TOTP). `console/tests/e2e/directory.spec.ts` (T066) automates it
  once `E2E_OPERATOR_PASSWORD` is set against this stack.
- Scenarios 1–3 as authenticated curl calls against freya-stack itself.
  Blocked for the same reason; covered by the integration suites above.
- Scenario 1 step 6 (delete a connection → users keep origin name) and
  Scenario 2 step 7 (LDAP `mail` change → re-import updates the e-mail). Both
  are covered only by the SQL `ON DELETE SET NULL`/`connection_name` design and
  the import unit tests, not by a live run.
- Scenario 3 step 3 (relay failure for one of three bulk activations): the
  stack's Mailpit accepts every domain, so a relay failure can't be produced.
- A TLS 1.2-only server (`allow_tls12`): the stack OpenLDAP offers TLS 1.3.
  Covered only by the `ldapdir` client tests.
- Rate limiting at 30/min across the gateway (unit only).
