# Quickstart: LDAP User Import (services/auth)

Validation scenarios proving the feature end to end. Assumes the `deploy/stack`
platform is up (TimescaleDB, Valkey, OpenFGA, Mailpit, gateway, auth) with the
optional `ldap` compose profile started (repo-owned OpenLDAP image, research
D17) and `configs/auth.yaml` allowing its network range in
`directory.targets.allow_cidrs`. Contracts:
[ldap-import-api.md](./contracts/ldap-import-api.md); data:
[data-model.md](./data-model.md).

## Prerequisites
- OpenLDAP seeded with `dc=example,dc=test`: `ou=Engineering` (5 people with
  `mail`), `ou=Sales` (3 people), one person without `mail`, two people sharing
  a `mail`, an alias under `ou=Engineering` pointing to `ou=Secret` (outside the
  connection base), a referral object, one entry with a 1 MiB `description`;
  service account `cn=reader,dc=example,dc=test`; ldaps on 636 and StartTLS on
  389 with a test CA (PEM available at `deploy/stack/ldap/ca.pem`).
- Tenant A: an owner and an admin; a custom role `directory-importer` holding
  only `directory:manage`; a member with no admin rights. Tenant B: an admin.
- Sign-in via the console (or curl with the session cookie) with a CSRF
  cookie/header pair for API calls.

## Scenario 1 — Connect a directory (US1)
1. Directories → New: kind OpenLDAP (mapping pre-filled `entryUUID`, `mail`,
   `displayName`, `givenName`, `sn`), URL `ldaps://openldap:636`, CA PEM,
   bind DN/password, base `ou=Engineering,dc=example,dc=test` → Test → `ok`,
   TLS 1.3 shown → Save → listed with last test `ok`.
2. GET the connection → body has `bind_password_set: true` and **no password**;
   grep the auth logs and `auth_audit_events` for the password → absent.
3. Test with a wrong password → `ok:false, step: bind, reason:
   invalid_credentials`; with host `openldap-missing` → `step: connect,
   unreachable`; without the CA → `step: tls, tls_failed`; base
   `ou=Nope,dc=example,dc=test` → `step: search_base, base_not_found`. No
   response contains the password or the server's diagnostic text.
4. Edit the name without a password → saved; Test still `ok` (stored password
   kept). URL `ldap://openldap:389` with `tls_mode: starttls` → `ok`.
5. `tls_mode: plain` → refused `insecure_transport` when `env: production`;
   accepted with a startup warning only with `directory.allow_plaintext: true`
   in a non-production config.
6. Delete a connection that has imported users → users stay, their origin shows
   the connection name.

## Scenario 2 — Filtered search and import (US2)
1. Import page → connection → filter `(&(objectClass=inetOrgPerson)(mail=*))` →
   preview lists only Engineering people with mail; statuses `new`; the alias
   target in `ou=Secret` is **not** returned (`out_of_scope` or not followed).
2. Filter `(objectClass=person` → `invalid_filter` shown immediately; the fake/
   container records **no** search.
3. Base `ou=Sales,dc=example,dc=test` (outside the connection base) →
   `invalid_base`; scope `one` vs `sub` changes the result set.
4. Set connection `size_limit: 2` → preview shows 2 entries + "more matched"
   (`truncated: true`).
5. Select 3 people + the no-mail person + both duplicate-mail people → Import →
   `created: 4`, `skipped: [no_email, duplicate_email]`; Mailpit receives
   **nothing**; Users list shows 4 × `imported` with origin; filter by status
   `imported` works.
6. Import the same selection again → `created: 0`, names refreshed
   (`updated`), no duplicates (SC-004).
7. Change a person's `mail` in LDAP and re-import → email updated while still
   `imported`.

## Scenario 3 — Activate via invitation (US3)
1. As tenant admin, Users → imported person → Activate with role `member` and a
   group → status `invited`; Mailpit shows the standard invitation within a
   minute (SC-003).
2. Accept the invitation link → set password (+ MFA if the policy requires) →
   status `active`, can sign in, directory origin still shown, group membership
   present.
3. Select three imported users → bulk Activate → three invitations, three
   `invited` rows; one user whose e-mail domain makes the relay fail stays
   listed as failed in the outbox retry while the other two proceed.
4. As an admin (not owner) activate with role `owner` → `403 self_escalation`,
   nothing sent. As the member (no admin) → `403 forbidden`.
5. Remove an imported user → deleted, no e-mail; removing an `active` user via
   `remove-imported` → `409 invalid_state`.
6. Plain "Invite user" with the e-mail of an imported person → that person
   becomes `invited` (no duplicate row).
7. Let an activation invitation expire (or resend) → resend works as for any
   invitation.

## Security checks (cross-cutting)
- **Filter injection / base escape** (SC-005): with the connection base filter
  `(departmentNumber=42)`, the filters
  `*)(|(objectClass=*)`, `x)(|(uid=*))(`, `(|(objectClass=*))`, NUL bytes and a
  6 KiB filter are refused or combined so the result never contains entries
  failing the base filter; the recorded effective filter is always
  `(&<base>(…))`.
- **TLS refusal**: plaintext in production refused; no API field disables
  certificate verification; a server cert from an unknown CA fails with
  `tls_failed`; TLS 1.2-only server fails unless `allow_tls12` is set.
- **SSRF target policy**: URLs `ldap://127.0.0.1:389`, `ldaps://[::1]:636`,
  `ldap://169.254.169.254:389`, a hostname resolving to 127.0.0.1,
  `ldap://timescaledb:5432` (port not allowed) and a stack-internal IP not in
  `allow_cidrs` → `target_refused`; responses do not distinguish closed from
  filtered ports; test/search beyond 30/min per tenant → `rate_limited`.
- **Password never returned**: sentinel password run through create/update/
  test/search/import; scan HTTP responses, logs, audit rows and errors → absent.
- **Imported user ≡ non-existent**: for an imported address vs a random
  address: `POST /api/v1/signin` → same `401 invalid_credentials` and timing
  class; 10 wrong attempts never yield `423 locked`; `POST /api/v1/recovery`
  → same `202`, no outbox row; `invitations/accept` with a forged token →
  `invalid_token`; deactivate→reactivate on an imported user → `409
  invalid_state` (no path to `active` without an invitation).
- **Cross-tenant**: tenant B admin GET/PUT/test/search/import/remove on tenant
  A's connection id → `404` and a `cross_tenant_refused` audit row; activate or
  remove-imported with tenant A user ids → per-user `not_found`; direct SQL as
  `auth_app` with tenant B context sees no tenant A rows in
  `directory_connections` / `user_directory_links`.
- **Audit**: connection create/update/delete/test, search (canonical filter +
  count), import (counts + user ids), activation (`invite_created` reason
  `activation`) and removal rows exist with actor and outcome; no names, e-mails
  or passwords in `details`.
