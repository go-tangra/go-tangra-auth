# Implementation Plan: User Groups & User Profiles

**Branch**: `004-groups-user-profiles` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-groups-user-profiles/spec.md`

## Summary

Extend the authentication service (feature 002) with tenant-scoped **groups** that
carry roles, so a user's effective roles are the union of direct bindings and
group roles, and with **profiles** (first name, last name, phone, avatar) that
the platform exposes through the session identity, the gateway's `/gateway/v1/me`
and the shell header. Group membership becomes a first-class relation in the
OpenFGA model (`role#assignee: [user, group#member]`), so every existing
`Check`/`BatchCheck` (and therefore every gateway decision) sees group-derived
access with no change to the decision path; mirror rows in PostgreSQL feed the
console, the audit trail and the "effective roles with sources" view. Session
views refresh their role list when the tenant's policy version moves, so the
next proof of identity carries the new effective roles without a sign-in.
Avatars are validated by content, re-encoded to a fixed 512×512 JPEG with the
standard library plus `golang.org/x/image` (WebP decode, resampling), stored in
the service's own database, and served only to signed-in users of the same
tenant under a content-addressed URL. The gateway learns two new identity
attributes (`display_name`, `avatar_url`), relays a refresh hint from the auth
module so a person's own profile edits bypass the identity cache, and the shell
header shows the name and picture.

## Technical Context

**Language/Version**: Go 1.26 (services), TypeScript 5 / Vue 3 / Vuetify 4 (console remote and shell)

**Primary Dependencies**: existing: Freya framework, Kratos v3, OpenFGA (via `internal/authz`), pgx + goose, valkey-go, kin-openapi, Module Federation runtime. New: `golang.org/x/image` (`webp` decoder, `draw` resampler) — see research.md R4.

**Storage**: PostgreSQL/TimescaleDB (new tables `groups`, `group_members`, `group_roles`, `avatars`; new columns on `users`; new audit event types), Valkey (existing session views and decision cache; no new key families), OpenFGA (new `group` type and relation).

**Testing**: Go `testing` (unit, contract, integration with testcontainers as in 002/003, fuzz for the avatar decoder and phone/name validators), Vitest (console and shell units), Playwright (console admin flows, shell header).

**Target Platform**: Linux server; browser console/shell (evergreen browsers).

**Project Type**: web service (auth) + federated frontend remote (console) + shell/gateway touch-points.

**Performance Goals**: decision latency for a user in 20 groups within 10% of direct-only (SC-003): OpenFGA resolves `group#member` in one query hop; the tenant-version decision cache is unchanged. Avatar processing ≤ 300 ms p95 for a 2 MB input on the reference box.

**Constraints**: avatar upload ≤ 2 MiB body (route-level override of the 1 MiB default, documented), decoded dimensions ≤ 4096×4096 checked before decoding (`image.DecodeConfig`), stored avatar ≤ 512×512 JPEG; phone never in logs/audit/tokens; cross-tenant answered `not_found`; group changes effective on the next decision (FGA write bumps the tenant version, which already busts the decision cache).

**Scale/Scope**: tenants with up to ~10k users and ~500 groups; groups with thousands of members (role change on a group is O(1) FGA writes, not O(members)); ~12 new HTTP endpoints, 1 new gRPC service (`Profiles`), 3 new console views, 1 shell header change.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Evaluate this feature against `.specify/memory/constitution.md` (v1.0.0).

- [x] **I. Secure by Default**: avatars are private (same tenant, signed in) with no public opt-in; group management is admin-only by default; the avatar body limit is a per-route override with a documented reason; the profile lookup is rate-limited by default. No new insecure options. PASS
- [x] **II. Zero Trust**: every new HTTP endpoint is declared in `console.yaml` and reached only through the existing session/bearer middleware and tenant guard; the new gRPC `Profiles` service runs on the Freya mTLS channel under `deploy/policy.yaml`; group mutations go through `authz.guard.Require` like role assignment; no handler can be reached without middleware (the `MustHandle` route table refuses undeclared routes). PASS
- [x] **III. Boundary Validation**: request schemas in OpenAPI (names ≤ 100 chars, E.164 phone pattern, group name ≤ 64, `additionalProperties: false`); avatar bytes validated by magic + `DecodeConfig` dimensions before decode, then re-encoded; per-route body limit; image decoders fuzzed. PASS
- [x] **IV. Test-First (NON-NEGOTIABLE)**: tasks will list tests first; negative tests for privilege escalation via groups (non-admin, cross-tenant, self-adding to owner-bearing group), disguised/oversized/bomb uploads, phone leakage scan; fuzz for avatar decoder, phone normaliser, name validator; contract tests for OpenAPI and proto; `internal/authz`, `internal/user/profile` (new) at 100%. PASS
- [x] **V. Observability**: new audit event types (`group.created/updated/deleted`, `group.member_added/removed`, `group.role_granted/revoked`, `profile.updated`, `avatar.updated/removed`); audit details carry field names only; phone marked PII and excluded from every log/event/response except self and admin profile reads; correlation IDs unchanged. PASS
- [x] **VI. Supply Chain**: one new module `golang.org/x/image` (Go project, maintained, no transitive deps) justified in research.md R4; no new frontend dependencies (Vuetify has avatar/file-input components); no cryptography. PASS
- [x] **VII. Simplicity**: groups are flat; effective roles are one SQL query plus the FGA relation (no materialised table); avatars in PostgreSQL bytea rather than an object store; refresh of session views piggybacks on the existing tenant version; no new config surface beyond `profile.avatar_max_bytes` (typed, defaulted). PASS
- [x] **Threat Model**: STRIDE table in research.md §Threat model. PASS

Post-design re-check (after Phase 1): unchanged, all PASS. The gateway change
(`X-Freya-Identity-Refresh` relay) adds one header-driven invalidation next to the
existing sign-out relay and is stripped before reaching the browser.

## Project Structure

### Documentation (this feature)

```text
specs/004-groups-user-profiles/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── console-api.delta.openapi.yaml   # new/changed HTTP endpoints
│   ├── auth.v1.delta.proto              # SessionIdentity fields + Profiles service
│   ├── authorization-model.fga          # full model with the group type
│   └── gateway-changes.md               # identity fields, refresh relay, shell header
└── tasks.md                             # /speckit-tasks
```

### Source Code (repository root)

```text
services/auth/
├── api/proto/auth/v1/auth.proto            # SessionIdentity{display_name, avatar_url}; service Profiles
├── api/openapi/console.yaml                # groups, profile, avatar, effective roles, lookup
├── internal/authz/
│   ├── model.fga                           # type group; role.assignee: [user, group#member]
│   ├── objects.go                          # GroupObject, GroupMembers
│   ├── groups.go (+_test)                  # Groups service: CRUD, members, roles, escalation guard
│   └── effective.go (+_test)               # EffectiveRoles(user) with sources
├── internal/user/
│   ├── profile.go (+_test)                 # Profile update, validation, phone normalisation
│   └── avatar.go (+_test, fuzz)            # decode/validate/normalise/encode
├── internal/session/session.go             # view carries PolicyVersion, DisplayName, AvatarURL; refresh on drift
├── internal/store/
│   ├── migrations/0004_groups_profiles.sql
│   ├── models.go / repos.go                # Group, GroupMember, Avatar, effective-role query
├── internal/httpapi/
│   ├── groups.go (+_test)                  # /api/v1/admin/groups…
│   ├── profile.go (+_test)                 # /api/v1/me/profile, /api/v1/me/avatar, admin profile, lookup, avatar serving
│   └── admin.go                            # effective roles endpoint; invitation groups
├── internal/grpcapi/profiles.go (+_test)   # Profiles.Lookup
├── internal/invite/                        # invitation carries groups + names
├── internal/audit/events.go                # new event types
├── pkg/authmanifest/manifest.go            # groups:manage permission, abilities, nav entry
├── console/src/
│   ├── views/admin/{Groups.vue,GroupDetail.vue}
│   ├── views/admin/UserDetail.vue          # profile editor, effective roles with sources, groups
│   ├── views/Account.vue                   # profile + avatar editor
│   ├── components/AvatarEditor.vue
│   ├── stores/session.ts                   # display_name, avatar_url; dispatch freya:session-changed
│   └── remote/{routes.ts,nav.ts}
└── tests/{contract,integration,fuzz}/      # groups_test, profile_test, avatar_fuzz_test, redaction scan

services/gateway/
├── internal/identity/identity.go           # Identity{DisplayName, AvatarURL}
├── internal/httpapi/{dispatch.go,me.go}    # X-Freya-Identity-Refresh relay; /me fields
├── api/openapi/gateway.yaml                # /me schema
└── shell/src/{stores/session.ts,layouts/Default.vue}  # header name + avatar; listen for freya:session-changed
```

**Structure Decision**: all new behaviour lives in `services/auth` following the
existing package split (domain packages under `internal/`, HTTP in
`internal/httpapi`, gRPC in `internal/grpcapi`, console under `console/`). The
gateway receives the minimum touch: two identity fields, one relayed header, and
the shell header. No new services or top-level packages.

## Complexity Tracking

No constitution violations. One deliberate override for the record:

| Item | Why Needed | Simpler Alternative Rejected Because |
|------|------------|-------------------------------------|
| Avatar route body limit 2 MiB (+ 64 KiB slack) instead of the 1 MiB default | phone photos routinely exceed 1 MiB before client-side resizing | forcing client-side resize only would leave the API unusable for non-browser clients; the limit is per-route, declared in the OpenAPI contract and the gateway manifest (`max_body_bytes`) |
