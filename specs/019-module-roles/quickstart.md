# Quickstart: validating module roles (019)

Automated (CI, auth): unit tests with the in-memory store and the OpenFGA
fake (registration, migration, roles, checks, escalation), integration
tests against PostgreSQL/Valkey/OpenFGA v1.20.0 (migration 0011 on a
database seeded with the pre-019 shape, `verify` and `prune-legacy`,
cross-module denial), fuzz targets for the qualified reference and object
id parsers, contract tests for the proto and OpenAPI, console vitest.
Portal: decider and shell tests with module-qualified keys. Modules: manifest
tests (roles valid, own permissions only) and a registration test against a
fake auth server.

Manual (freya-stack, after auth + gateway + at least warden and ipam are
upgraded):

1. Before upgrading, record effective permissions:
   `authsvc permissions verify -snapshot /tmp/before.json`.
2. Upgrade auth, then the gateway. Admin → Roles still shows the old roles;
   every signed-in user keeps their access (spot-check warden and ipam pages).
3. Upgrade warden and ipam. `authsvc permissions verify
   -compare /tmp/before.json` → no losses; gains only as the per-module split.
4. Admin → Roles: "Warden administrator", "Warden editor", "Warden viewer",
   "IPAM administrator|operator|viewer" with module badges.
   Opening "Warden viewer" shows it read-only with a Clone button.
5. Admin → Roles → New role: sections "Authentication", "IPAM", "Warden", …;
   "backup: manage" appears under both IPAM and Warden. Select all in Warden
   as a delegated role manager selects only permissions they hold.
6. Assign "Warden viewer" to a test user: warden secrets readable, writes
   refused; IPAM pages not in the navigation.
7. Create a custom role with only `warden:backup:manage`: warden backup
   export works; ipam backup export → 403.
8. Create a new tenant: module roles and `auditor` exist immediately (no
   5-minute wait); audit shows `module_registered` for the registrations.
9. Remove the "viewer" role from warden's manifest in a dev build and
   restart warden: "Warden viewer" shows `retired`, existing assignment
   still works, assigning it to someone else → "role_retired".
10. After every module is upgraded: `authsvc permissions prune-legacy
    -dry-run`, then without `-dry-run`; the "Before modules" section
    disappears; access unchanged (repeat step 3).
