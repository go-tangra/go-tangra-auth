# Research: User Groups & User Profiles

All technical-context unknowns were resolvable from the existing services; no
`NEEDS CLARIFICATION` remained. Each decision below records what was chosen,
why, and what was rejected.

## R1. Where group membership lives in the authorization model

**Decision**: add `type group` with `member: [user]` to the OpenFGA model and
widen `role.assignee` to `[user, group#member]`. A group holding a role is one
tuple `group:T/finance#member assignee role:T/auditor`; membership is one tuple
`user:U member group:T/finance`. `Check(user:U, granted, permission:T/x)` then
resolves through the group with no change to `Decider`, `BatchCheck`, or the
gateway.

**Rationale**: the decision path is the security-critical code and stays
untouched; union semantics (FR-004) are native to the relation graph; adding a
role to a group of 5,000 members is one write, not 5,000 (edge case "very large
groups"); removing a member is one delete and is visible on the next check
(SR-005) because `Client.Write` already bumps the tenant policy version that
keys the decision cache.

**Alternatives rejected**: (a) expanding group roles into per-user
`role_bindings` rows and FGA tuples on every membership change — O(members)
writes, drift risk, and no way to show "via group"; (b) resolving effective
roles in SQL on every check and bypassing FGA — duplicates the policy engine
and breaks Principle II's "one policy engine" intent.

## R2. Effective roles in the session view and proof of identity

**Decision**: the session `view` stored in Valkey gains `PolicyVersion`
(the tenant version at the time roles were loaded). `Resolve` compares it with
the current tenant version (one cache `GET`, already used by decisions); on
drift it reloads effective roles from the database (`EffectiveRoleSlugs`,
one query joining direct bindings and group roles), rewrites the view, and
continues. Tokens minted from then on (`Sessions/Exchange`, `MintToken`,
`/api/v1/session/token`) carry the new roles. Previously issued tokens keep
their roles until expiry (≤ 1 h), which SR-005 permits because every
consulting service asks the auth service for decisions.

**Rationale**: zero per-member work on group changes; also fixes a latent gap
in feature 002 where a direct role change was not reflected in a cached view
until the idle TTL elapsed. One extra `GET` per resolve on a key that Valkey
serves from memory.

**Alternatives rejected**: evicting every cached view of every affected user
(needs a user→session index and O(members) work); embedding group ids in the
token and expanding at verification time (bloats the token, makes offline
verifiers policy-aware).

## R3. Effective roles with sources for the console

**Decision**: a single SQL query returns `(role_id, slug, source_kind,
group_id, group_name)` rows from `role_bindings UNION ALL group_roles JOIN
group_members`; the service folds them into `[{role, sources: [{kind: direct}
| {kind: group, group_id, group_name}]}]`. Not stored, not cached (admin
screens only).

**Rationale**: FR-007 wants provenance, which FGA does not expose cheaply
(`Expand` is per-relation and verbose); the mirror rows already exist for
direct bindings.

## R4. Avatar processing pipeline and the `golang.org/x/image` dependency

**Decision**: accept PNG, JPEG, WebP. Pipeline: (1) body limit 2 MiB + 64 KiB
at the route; (2) sniff the first 512 bytes (`http.DetectContentType`) and
refuse anything but the three types; (3) `image.DecodeConfig` on the bytes and
refuse width×height > 16,777,216 (4096×4096) **before** decoding; (4)
`image.Decode` with the three decoders registered (stdlib `image/png`,
`image/jpeg`, `golang.org/x/image/webp`); (5) centre-crop to a square, scale
to ≤ 512 with `golang.org/x/image/draw` (CatmullRom); (6) composite onto white
and encode as JPEG quality 85 (`image/jpeg`); (7) store bytes + `sha256`, set
`users.avatar_id`. Served with `Content-Type: image/jpeg`,
`X-Content-Type-Options: nosniff`, `Content-Disposition: inline;
filename="avatar.jpg"`, `Content-Security-Policy: sandbox`, `Cache-Control:
private, max-age=31536000, immutable`; the URL embeds the content hash so a
change is a new URL (FR-015).

**Dependency justification (Principle VI)**: `golang.org/x/image` is maintained
by the Go project, has no third-party transitive dependencies, and provides the
only WebP decoder and a quality resampler outside the standard library.
Alternatives: `github.com/disintegration/imaging` (unmaintained, wraps x/image
anyway), `libvips` bindings (cgo, large attack surface), dropping WebP (spec
requires it). Version pinned in `go.mod`; `govulncheck` in CI.

**Rationale for JPEG-only output**: one fixed content type simplifies SR-003
(no SVG, no animated formats, no metadata since the encoder writes none),
photos compress ~10× better than PNG; transparency is rare in avatars and is
composited onto white. Animated WebP/GIF: GIF is not accepted; the WebP decoder
returns the first frame.

**Decompression-bomb defence**: the dimension check on `DecodeConfig` bounds
memory at 4096×4096×4 B = 64 MiB per decode; the handler additionally runs
decodes under a semaphore of 4 concurrent decodes per instance.

## R5. Phone number validation

**Decision**: normalise by removing spaces, hyphens, dots and parentheses, then
require E.164 `^\+[1-9][0-9]{6,14}$`; store the normalised string; no
`libphonenumber`. Optional field; empty clears it.

**Rationale**: the spec asks for "valid international format", not
carrier-level validation; a regex is fuzzable and dependency-free.
**Rejected**: `github.com/nyaruka/phonenumbers` (large metadata blob, frequent
updates, adds ~5 MB).

## R6. Phone privacy and redaction

**Decision**: `phone` appears only in `GET/PUT /api/v1/me/profile` (self) and
`GET/PUT /api/v1/admin/users/{id}/profile` (admin). It is absent from
`/api/v1/session`, `SessionIdentity`, tokens, `/gateway/v1/me`, the profile
lookup and user lists. Audit events for profile changes carry
`details.fields: ["first_name","phone"]` (names only). The structured logger's
redaction list gains `phone`, `first_name`, `last_name` (Principle V); the
redaction scan test from feature 003 is extended with a phone corpus.

## R7. Propagating profile changes to the gateway and shell

**Decision**: `SessionIdentity` (and `Exchange`/`MintToken` responses) carry
`display_name` and `avatar_url`. The gateway's `Identity` struct and
`/gateway/v1/me` expose them; the shell header renders them. The gateway caches
session identities for 60 s; to make a person's **own** edits visible on the
next page load (US2 scenario 2), the auth module answers profile/avatar
mutations with `X-Freya-Identity-Refresh: 1`, and the gateway's dispatcher
(which already watches for the sign-out relay) drops the cached identity for
that cookie and strips the header before it reaches the browser. Inside the
page, the console remote dispatches a `freya:session-changed` DOM event after a
successful save; the shell listens and refetches `/gateway/v1/me`. Admin edits
of **other** users propagate within the 60 s TTL (spec amended accordingly).

**Rationale**: reuses an existing relay hook, keeps the gateway ignorant of
profiles, no cross-store coupling between the auth and gateway Valkey
namespaces.
**Rejected**: a user→cache-key index in the gateway (needs sets, multi-instance
consistency); overloading the revocation feed with a "profile" kind (it is a
security primitive with a closed vocabulary and a DB `CHECK`); shortening the
identity cache TTL (raises Exchange load for everyone).

## R8. Display name derivation and compatibility

**Decision**: `display_name` stays a stored column. `users.display_name_explicit
boolean` records whether it was ever set by hand; when false, the service
recomputes `display_name = trim(first_name || ' ' || last_name)` on profile
save (falling back to the previous value, then email local part). Existing
users are untouched by the migration (`first_name`, `last_name`, `phone` empty;
`avatar_id` null), satisfying SC-009.

## R9. Group management authorisation and escalation

**Decision**: group create/update/delete, membership and group-role changes
require `users:manage` **and** pass the same escalation guard as direct role
assignment: an actor who is not an owner cannot grant, through a group, a role
that grants permissions the actor does not hold (`Escalation.MayGrant`), and
cannot add a member to a group that carries `owner`/`admin` unless they hold
that role. Adding oneself to a group is allowed only under the same rule (it
is never a way to gain what one could not grant). Deleting a group requires
`{"member_count": N}` matching the current count (FR-008).

**Rationale**: mirrors `Assigner.AssignRoles` so groups cannot become an
escalation side door (threat T3).

## R10. Console permission and abilities

**Decision**: one new permission `groups:manage` (granted to owner, admin,
operator), one ability `manage Group`, one nav entry "Groups" under the admin
section. Profile self-service is covered by the existing `profile:read` (the
ability `update Profile` already exists). The lookup `GET /api/v1/users/{id}`
needs only a session (any tenant member).

## R11. Invitation extension

**Decision**: `POST /api/v1/admin/invitations` accepts `group_ids`,
`first_name`, `last_name`; they are stored on the invitation row; on acceptance
the user row gets the names and joins the groups that still exist (missing
ones listed in `details.skipped_groups` of the audit event). The invitation
email is unchanged.

## Threat model (STRIDE)

| # | Threat | Category | Control |
|---|--------|----------|---------|
| T1 | Non-admin adds themselves to "Admins" group | Elevation | `users:manage` + escalation guard (R9); refusal audited |
| T2 | Admin of tenant A adds a user of tenant B to a group | Tampering / Info | tenant guard on every object; cross-tenant ids answered `not_found` (SR-002) |
| T3 | Group used to grant a role the actor could not grant directly | Elevation | same `MayGrant` check as direct assignment (R9) |
| T4 | Stale access after removal from a group | Elevation | FGA write bumps tenant version → decision cache miss; session view reload on version drift (R2); tokens ≤ 1 h |
| T5 | Polyglot/disguised upload (HTML as .png) | Tampering | content sniffing + decoder + re-encode; fixed `image/jpeg`, `nosniff`, `sandbox` CSP (R4) |
| T6 | Decompression bomb / huge dimensions | DoS | 2 MiB body limit; `DecodeConfig` dimension gate before decode; decode semaphore |
| T7 | EXIF GPS or embedded profile data leaks | Info disclosure | re-encode writes pixels only |
| T8 | Avatar URL guessed across tenants | Info disclosure | session required; tenant of the caller must equal the user's tenant; content hash in URL is not a capability |
| T9 | Phone number in logs, audit, tokens, `/me` | Info disclosure | field never serialised outside self/admin profile endpoints; logger redaction; scan test (R6) |
| T10 | User enumeration via lookup | Info disclosure | tenant-scoped, session required, rate-limited, uniform `not_found` |
| T11 | Forged `X-Freya-Identity-Refresh` from the browser | Spoofing | the gateway honours the header only on responses from the auth module and strips it inbound and outbound |
| T12 | Concurrent group edits lose a membership change | Repudiation / Integrity | membership and role rows are individually inserted/deleted with unique constraints; each change audited |
| T13 | Group deletion by accident wipes access | Availability | member-count confirmation (FR-008); audit lists roles and member count |
