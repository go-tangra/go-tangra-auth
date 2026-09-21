# Security Review: User Groups & User Profiles

**Purpose**: Map every threat in `research.md` (STRIDE table) to the control that implements it and the test that proves it
**Created**: 2026-09-16
**Feature**: [spec.md](../spec.md)

| # | Threat | Control | Evidence (test) |
|---|--------|---------|-----------------|
| T1 | Non-admin adds themselves to "Admins" | `authz.Groups.admin` (owner/admin only) + escalation guard on privileged groups | `TestGroupEscalationAndIsolation`, `TestGroupHandlers` (member 403, refusal audited) |
| T2 | Cross-tenant group/member access | tenant guard on every object; RLS on the new tables; cross-tenant ids → `not_found` | `TestGroupRepos` (RLS), `TestGroups` (globex admin), `TestGroupEscalationAndIsolation` |
| T3 | Group grants a role the actor could not grant directly | `Escalation.MayGrant` on group roles and on membership; `owner` never via a group | `TestGroupEscalationAndIsolation`, `TestGroupHandlers` (self_escalation) |
| T4 | Stale access after removal | FGA write bumps the tenant version → decision cache miss; session views reload on version drift; tokens ≤ 1 h | `TestGroups` (refused after remove/revoke/delete, session roles refresh), `TestViewRefreshOnPolicyVersion` |
| T5 | Disguised upload (HTML as .png, SVG, GIF) | content sniff + decode + re-encode; fixed `image/jpeg`, `nosniff`, sandboxed CSP | `TestAvatarNormaliseRefuses`, `TestProfileHandlers` (headers), `TestProfile` (integration) |
| T6 | Decompression bomb / huge dimensions | `image.DecodeConfig` pixel gate before decode; 2 MiB route limit; decode semaphore | `TestAvatarBombNeverDecodes`, `TestAvatarConcurrencyLimit`, `FuzzAvatarDecode` (30 s clean) |
| T7 | EXIF/ICC leakage | re-encode writes pixels only | `TestAvatarNormaliseAcceptsAndStrips` (`exif-gps.jpg`), `TestProfile` |
| T8 | Avatar guessed across tenants | session required; caller tenant must equal user tenant; uniform 404 | `TestProfileHandlers`, `TestProfile` (anonymous, globex) |
| T9 | Phone in logs/audit/tokens/`/me` | phone only on self/admin profile endpoints; audit carries field names; framework redacts `phone` keys; scan pattern `+38591` | `TestGroupAndProfileEvents`, `TestProfileHandlers` (session document), `TestRedactionScan`, `TestRedactsForbiddenKeys` (framework), `TestMeCarriesProfile` |
| T10 | User enumeration via lookup | tenant-scoped, session required, rate-limited, uniform `not_found` | `TestProfileHandlers` (429, foreign/unknown 404), `TestProfilesLookup` (gRPC omits unknown ids) |
| T11 | Forged `X-Freya-Identity-Refresh` | dispatcher drops the inbound header, strips it outbound, honours it only from the auth module | `TestIdentityRefreshRelay` |
| T12 | Concurrent edits lose a change | membership/role rows are individually inserted with PK constraints; each change audited | `TestGroupRepos` (idempotent add), `TestGroups` (audit counts) |
| T13 | Accidental group deletion | member-count confirmation; audit lists roles and count | `TestGroupLifecycleGrantsAndWithdrawsAccess`, `TestGroupHandlers` (409), console `groups.spec.ts` |

## Gates

- [x] `go vet`, `staticcheck`, `gosec`, `govulncheck` clean (auth and gateway)
- [x] Coverage gate: total 82.9 %; `internal/{token,session,password,mfa,tenantctx}` 100 %; new files `internal/user/{profile,avatar}.go` 100 %; `internal/authz/groups.go` covered by unit + integration (package-level 100 % not gated: pre-existing SDK bindings in `fga.go` need a live OpenFGA)
- [x] Fuzz: `FuzzAvatarDecode` 30 s, `FuzzPhone` 10 s, `FuzzName` seeds, no findings
- [x] `npm audit --omit=dev`: 0 (console, shell)
- [x] Redaction scan pattern for the fixture phone number added to `scripts/redaction-scan.sh`

## Notes

- `internal/user` as a package is at 93 %: the remaining branches are pre-existing error paths in `admin.go`/`signin.go` (feature 002) outside this feature's scope; the gate list was left unchanged so it stays honest.
- Administrators' edits of other users reach the platform within the gateway identity cache window (60 s); the spec was amended to say so (US3 scenario 2, SC-004).
