# Quickstart results — User Groups & User Profiles

Run on 2026-09-16 against the local platform stack (auth in gateway mode +
gateway with the shell + hello module; TimescaleDB, Valkey, OpenFGA, Mailpit
from `services/gateway/deploy/compose.yaml`), plus a second, standalone auth
instance (`deploy/dev-standalone.yaml`, port 8543) sharing the database for the
console Playwright suite.

| § | Scenario | Result |
|---|----------|--------|
| 1 | Gates: `go vet`, `staticcheck`, `gosec`, `govulncheck` (auth, gateway); coverage gate total 82.9 % with `internal/{token,session,password,mfa,tenantctx}` at 100 %; fuzz `FuzzAvatarDecode` 30 s / `FuzzPhone` 10 s clean; console 37 and shell 28 unit tests; `npm audit --omit=dev` 0 (both); contract tests | ✅ |
| 2 | Groups grant access: `TestGroups` (allowed within 1 s of adding, refused after remove / role revoke / group delete, direct + group sources, deactivated member denied, session roles refresh without re-login, audit counts, cross-tenant 404); `TestGroupDecisionLatency` p95 direct 14.4 ms vs 20 groups 17.2 ms on the 4-core workstation — within the 10 % + 2 ms floor of the test (SC-003 confirmed on this box, not on sized hardware); console `groups.spec.ts` (create → role → member → "via <group>" → delete with count) | ✅ |
| 3 | Own profile: `TestProfile` (names/phone, avatar corpus incl. HTML-as-PNG, 20000² bomb, truncated JPEG, 3 MiB body → 413, EXIF stripped, content-hash URL changes on replace, cross-tenant/anonymous avatar and lookup 404, phone absent from session/identity), `TestRedactionScan` with the phone pattern; console `profile.spec.ts` (save, reload, upload, remove, disguised file refused) | ✅ |
| 4 | Admin edits: `TestAdminProfile` (member 403, admin edit visible to the subject on the next request, avatar removal, search by name, audit actor/subject); console `admin.spec.ts` "user detail: profile panel" | ✅ |
| 5 | Invitation into groups: `TestInviteIntoGroups` (group roles apply on acceptance, deleted group skipped, names on the profile); console `admin.spec.ts` "invite into a group with names" | ✅ |
| 6 | Platform surfaces: gateway `TestIdentityRefreshRelay`, `TestMeCarriesProfile`, identity cache test; shell `profile.spec.ts` — editing the profile in the auth remote updates the shell header name and avatar without sign-out, survives a full navigation, avatar removal clears it (5/5 shell specs pass) | ✅ |
| 7 | Upgrade safety: `TestUpgrade` (hand-set display names kept, email-shaped ones yield to names, existing session and token keep working); migrations `0005`/`0006` applied to the running dev database without a re-sign-in | ✅ |

## Notes

- **Pre-existing failures fixed on the way** (all outside this feature but blocking the suite):
  key rotation inserted the new active key before retiring the old one (unique index
  refused it); `RevokeUser` with a kept session listed live sessions *after* marking
  them, so the others' cached views survived; the session revocation vocabulary did not
  match the database check constraint (migration `0006`); the audit query had a zero
  upper bound and returned nothing without a `to` filter; the console Playwright config
  used `data-testid` while the views use `data-test`; console nav `role="list"` and
  medium-emphasis text failed axe; three integration tests had stale expectations
  (CSRF header on the oversized-body case, CSRF cookie issued to anonymous browsers,
  two role revocations, second-granularity token issue time).
- The console Playwright suite runs against a standalone instance because a direct
  `/console/...` URL through the gateway loads the console as a full page (feature 003
  behaviour); the shell suite covers the in-shell path.
- The repeated console runs hit the sign-in rate limit (20 per account per 10 min);
  counters were cleared between runs.
- `internal/user` is at 93 % package coverage: the new `profile.go`/`avatar.go` are at
  100 %; the remainder is pre-existing feature 002 error paths.
