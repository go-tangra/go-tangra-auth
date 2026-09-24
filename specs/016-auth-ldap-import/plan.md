# Implementation Plan: LDAP User Import for the Auth Service

**Branch**: `016-auth-ldap-import` | **Date**: 2026-09-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/016-auth-ldap-import/spec.md`

## Summary

Tenant administrators connect services/auth to their LDAP directory (Active
Directory, OpenLDAP or other) over TLS, search it with an RFC 4515 filter that
is validated, canonicalised and AND-combined with the connection's base filter
under the connection's base DN, preview matching people with their platform
status, and import the selected ones as users in a new inactive status
**`imported`** (no password, no e-mail, indistinguishable from a non-existent
account at sign-in, reset and recovery). An administrator holding the existing
invite capability then **activates** imported users — singly or in bulk,
choosing roles and groups — which runs the existing invitation path (token,
72 h expiry, standard e-mail) and moves them to `invited`; the unchanged
invitation acceptance makes them `active`. The feature lives entirely inside
services/auth: a new pure LDAP boundary package (`internal/ldapdir`: dial-time
SSRF target policy, TLS config, filter/DN validation, attribute mapping), a
domain service (`internal/directory`) with a sealed bind password (existing KEK
envelope), one migration (connections + directory links + status CHECK), new
console routes/pages and targeted hardening of sign-in, deactivate/reactivate
and invitation role grants so `imported` can never become `active` without an
invitation.

## Technical Context

**Language/Version**: Go 1.26 (services/auth module); console TypeScript/Vue 3
with the `@freya/ui` kit (FlyonUI/Tailwind, zod).

**Primary Dependencies**: existing auth stack (Freya framework, pgx +
TimescaleDB, Valkey cache, OpenFGA, `internal/crypto` envelope, outbox e-mail);
**new**: `github.com/go-ldap/ldap/v3` (+ transitive `go-asn1-ber/asn1-ber`,
`Azure/go-ntlmssp`) — not present in any repository `go.sum` today; justified in
research D2 and the supply-chain note.

**Storage**: auth's TimescaleDB database. Migration
`0008_ldap_import.sql`: `directory_connections` (RLS, sealed
`bind_password_enc`), `user_directory_links` (RLS, unique `(tenant_id,
connection_id, directory_uid)`), `users.status` CHECK gains `imported`. Import
runs/searches are audit events in the existing `auth_audit_events` hypertable
(no new run table).

**External systems**: customer LDAP servers reached **outbound** from the auth
container over ldaps (636/3269) or StartTLS (389/3268), through a policy-
checked dialer. No new inbound surface, no new mesh peer.

**Testing**: Go `testing`; `ldapdir` table + fuzz tests (100 % coverage gate);
`ldapdir/ldapfake` in-memory directory so `directory`, `invite` and `httpapi`
tests run offline; `memstore` extended; negative security tests (filter
injection, base escape, TLS/plaintext refusal, SSRF targets, password
redaction, imported-vs-unknown at sign-in/recovery/accept, cross-tenant,
escalation at activation); contract test over console.yaml; integration suite
(`//go:build integration`) with the existing TimescaleDB/Valkey/OpenFGA harness
plus a repo-owned Alpine OpenLDAP container (ldaps + StartTLS + test CA). Console:
vitest unit + Playwright e2e.

**Target Platform**: the existing auth container in `deploy/stack`; optional
compose profile `ldap` with the same OpenLDAP image for manual/e2e testing.

**Project Type**: feature inside an existing web service (Go HTTP API + embedded
Vue console).

**Performance Goals**: 50,000-entry directory preview < 10 s (SC-007 — server
size limit ≤ 1000, attribute allow-list, one search); import of 100 people
< 5 min end to end (SC-001 — one re-fetch search + per-entry transactions);
activation e-mail < 1 min (SC-003 — existing outbox worker).

**Constraints**: TLS mandatory outside development (TLS 1.3 default, TLS 1.2
per-connection opt-out); bind password sealed, write-only, never
logged/audited/returned/echoed in errors; dial-time IP/port target policy;
per-tenant RLS on all new tables; imported accounts never reach `active`
without `invite.Accept`; no directory PII in audit beyond ids/counts and the
admin-typed filter.

**Scale/Scope**: ≤ 10 connections per tenant; preview ≤ 1000 entries; import
≤ 500 per request; activation ≤ 100 per request; three P1 user stories (connect,
search + import, activate).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Secure by Default**: plaintext LDAP refused unless
  `!IsProduction() && directory.allow_plaintext` (warned at startup, audited on
  save); no skip-verify option exists; TLS 1.3 minimum unless a connection
  explicitly opts into TLS 1.2 with approved ciphers; the target policy denies
  loopback/link-local/metadata/unspecified/multicast always and platform CIDRs
  by default, and only ports 389/636/3268/3269; imported users are inactive by
  construction. PASS.
- **II. Zero Trust Service Communication**: the feature adds an **outbound
  network client from auth to customer-controlled directories** — external
  systems that cannot be mesh peers (no SPIFFE). They are treated as untrusted:
  server identity is verified by TLS (system roots or a pinned per-connection
  CA), the directory is used only as a data source (never for authentication),
  every returned entry is re-validated (DN inside the base, bounded values),
  imports re-fetch from the directory rather than trusting browser-supplied
  entries, and the dialer refuses platform-internal targets so the client
  cannot be turned against mesh services. Browser access remains session +
  CSRF + per-route authorization in handler code. PASS (non-mesh external
  peer recorded in Complexity Tracking).
- **III. Boundary Validation & Defense in Depth**: request schemas in
  console.yaml (`additionalProperties: false`, lengths, enums); filters
  compiled by an RFC 4515 compiler, depth/size-capped, canonicalised and
  AND-combined; DN scoping; alias dereferencing off; referrals ignored; size/
  time limits enforced server- and client-side; BER packet cap; per-value caps;
  RLS + tenant-scoped queries + cross-tenant audit; rate limits on test/search.
  PASS.
- **IV. Test-First with Security Verification (NON-NEGOTIABLE)**: tests precede
  implementation per task ordering; negative tests for injection, base escape,
  TLS downgrade/untrusted CA, SSRF (literal, DNS-resolved, port), password
  leakage (sentinel scan of responses/logs/audit/errors), enumeration via
  imported accounts (response, timing class, lockout), deactivate→reactivate
  bypass, escalation at activation, cross-tenant ids; fuzz tests for filter
  compile/combine, DN scoping, URL parsing and attribute decoding; contract
  test for every new route; `internal/ldapdir` added to the 100 % coverage set
  in `scripts/coverage-gate.sh` (auth is an `auth/` package per Principle IV).
  PASS.
- **V. Observability & Auditability**: append-only audit events for connection
  create/update/delete/test, search (canonical filter + count), import (counts
  + user ids), activation (`invite_created` reason `activation`), imported-user
  removal and policy refusals; structured logs carry LDAP result codes, never
  server diagnostic text or credentials; the new routes are covered by the
  framework's request metrics/traces on the existing listeners (auth has no
  service-specific metrics today; none are added — YAGNI); `make
  redaction-scan` extended to the new packages. PASS.
- **VI. Supply Chain Integrity & Minimal Dependencies**: one new direct
  dependency (`go-ldap/ldap/v3`) justified in research D2 (maintained, MIT,
  widely deployed; hand-writing an LDAP/BER client would be a larger attack
  surface); pinned via `go.sum`, `govulncheck` in `make vuln`; TLS from stdlib;
  sealing from the existing `internal/crypto`; test image built from a pinned
  Alpine digest in-repo rather than an unmaintained third-party image. PASS.
- **VII. Simplicity & Explicit Configuration**: typed `directory` config section
  validated at start; no background workers, no sync scheduler, no new service,
  no run table (audit is the record); activation reuses the invitation code
  path; the LDAP boundary is one package with a two-method interface and a
  fake. PASS.

No unjustified violations. Post-design re-check (after data-model, contracts,
quickstart): PASS — the only new trust boundary is the one listed in the spec
(auth → customer LDAP), recorded below with its compensating controls. Two
pre-existing weaknesses found while grounding the design are fixed as part of
this feature because `imported` would make them exploitable or FR-008 requires
it: the sign-in lockout oracle for known-but-inactive accounts and the
`deactivated → active` reactivation without a password (research D10), and the
missing role-escalation check on invitations (research D11 — behaviour change
to plain invitations, flagged to the requester).

## Project Structure

### Documentation (this feature)

```
specs/016-auth-ldap-import/
├── plan.md              # This file
├── research.md          # Phase 0 output (D1–D18, supply chain, STRIDE)
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── ldap-import-api.md   # console HTTP routes, manifest, internal interfaces, audit
└── tasks.md             # Phase 2 output (/speckit-tasks)
```

### Source Code (new and changed paths only)

```
services/auth/
├── go.mod / go.sum                              # + github.com/go-ldap/ldap/v3
├── api/openapi/console.yaml                     # + /api/v1/admin/directories*, /users/activate, /users/{id}/remove-imported; User.status += imported (v1.2.0)
├── pkg/authmanifest/manifest.go                 # + directory:manage permission, grants, ability, nav "Directories"; Version 1.2.0
├── internal/
│   ├── ldapdir/                                 # NEW — LDAP boundary (100 % coverage)
│   │   ├── policy.go                            #   TargetPolicy: URL check + net.Dialer Control (IP/port, always-deny set)
│   │   ├── tlsconf.go                           #   tls.Config from CA PEM / system roots, TLS 1.3 default, 1.2 opt-in suites
│   │   ├── filter.go                            #   CompileUserFilter, Combine, depth/size caps, :dn: refusal
│   │   ├── dn.go                                #   ScopeBase, WithinBase
│   │   ├── mapping.go                           #   DefaultMapping(kind), Decode (objectGUID, caps, email norm)
│   │   ├── client.go                            #   Directory/Session over go-ldap (DialURL, StartTLS, SimpleBind, Search)
│   │   ├── errors.go                            #   closed error set; LDAP result code mapping
│   │   └── ldapfake/fake.go                     #   in-memory Directory for offline tests
│   ├── directory/                               # NEW — domain service
│   │   ├── directory.go                         #   connections CRUD, sealing (crypto.Envelope, AD ldap-bind:<tid>:<id>)
│   │   ├── test.go search.go import.go          #   Test / Search (preview status) / Import (re-fetch by uid, per-entry tx)
│   │   └── directorydb/db.go                    #   pgx store under store.Scope
│   ├── store/
│   │   ├── migrations/0008_ldap_import.sql      #   tables, RLS, grants, users.status CHECK += imported
│   │   ├── directory.go                         #   models DirectoryConnection, DirectoryLink + SQL
│   │   ├── models.go repos.go groups.go         #   ListUsers join for origin; AddGroupMembers excludes imported
│   │   └── migrate_test.go                      #   migration assertions
│   ├── memstore/directory.go                    #   in-memory connections + links (same uniqueness)
│   ├── invite/invite.go                         #   Activate(); CreateWith converts imported; escalation dependency
│   ├── authz/assign.go                          #   MayAssign extracted from AssignRoles (shared by invitations)
│   ├── user/signin.go                           #   imported ⇒ unknown account (no lockout)
│   ├── user/admin.go                            #   RemoveImported; Deactivate/Reactivate refuse imported
│   ├── audit/audit.go                           #   + directory_* and imported_user_deleted event types
│   ├── config/config.go                         #   + Directory section (targets, limits, allow_plaintext) + Warnings
│   ├── httpapi/directory.go                     #   NEW handlers + RequirePermission helper
│   ├── httpapi/admin.go                         #   activate, remove-imported, invalid_state mapping
│   └── app/app.go                               #   wire ldapdir policy/client, directory service, routes
├── console/src/
│   ├── views/admin/Directories.vue              #   NEW list + DirectoryDrawer.vue (create/edit/test/delete)
│   ├── views/admin/DirectoryImport.vue          #   NEW filter → preview → select → import result
│   ├── views/admin/ActivateDrawer.vue           #   NEW roles/groups pickers, single + bulk
│   ├── views/admin/Users.vue                    #   imported chip/filter, origin, activate/remove, multi-select
│   ├── api/vocab.ts, schemas/directory.ts       #   status + zod schemas
│   ├── router/routes.ts, remote/{routes,nav}.ts #   /admin/directories, /admin/directories/import
│   └── tests/{unit,e2e}/directory*.spec.ts      #   vitest + Playwright
├── tests/
│   ├── contract/openapi_test.go                 #   new routes declared; no readable password field
│   ├── fuzz/ldap_fuzz_test.go                   #   filter/DN/URL/mapping fuzzers
│   └── integration/ldap_import_test.go          #   OpenLDAP container end to end
│       └── testdata/openldap/                   #   Dockerfile (alpine, pinned), slapd config, people.ldif
├── scripts/coverage-gate.sh                     #   + internal/ldapdir in SECURITY_PKGS
└── deploy/README / docs                         #   directory section: target policy, TLS, dev opt-outs
deploy/stack/
├── compose.yaml                                 # + optional `ldap` profile service (same Dockerfile)
└── configs/auth.yaml                            # + directory section (allow_cidrs for the stack LDAP)
```

**Structure Decision**: extend services/auth in place, following its existing
package conventions (`<domain>` + `<domain>db`, `memstore`, `httpapi` handler
files per area, goose migrations, console views under `views/admin`). The
outbound LDAP client is isolated in `internal/ldapdir` — pure functions plus a
two-method interface with an in-memory fake — so the security-critical
parsing/policy code is fuzzable and 100 %-covered without a directory, and the
domain service never touches go-ldap directly.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| Outbound connections from auth to customer-controlled LDAP servers (non-mesh peers, no SPIFFE) | The feature's purpose (FR-001–FR-006); directories are customer infrastructure | Cannot be mesh peers. Compensated by: TLS with verification (system roots or pinned CA), no skip-verify, dial-time IP/port target policy with always-deny set, coarse error vocabulary, rate limits, directory never used for authentication, all returned data re-validated (research D3, D5–D7). |
| New dependency `github.com/go-ldap/ldap/v3` (+2 transitive) | LDAPv3 protocol, RFC 4515 filter compiler, RFC 4514 DN parser | A hand-written BER/LDAP client and filter parser would be a larger, less-tested security-critical surface (research D2). |
| Per-connection TLS 1.2 opt-out | Active Directory on Windows Server < 2022 offers only TLS 1.2 | A global 1.2 floor weakens every tenant; the opt-out is explicit, per connection, with approved AEAD/ECDHE suites (Constitution transport rule). |
| Behaviour change to existing auth paths (sign-in known-account check, deactivate/reactivate, invitation role escalation) | `imported` would otherwise be enumerable (lockout oracle) or activatable without an invitation; FR-008 demands escalation rules | Leaving them unchanged violates SR-006/FR-005/FR-008 (research D10, D11). Plain invitations gain the same escalation check as `setUserRoles`. |
