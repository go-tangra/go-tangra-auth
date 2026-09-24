# Feature Specification: LDAP User Import for the Auth Service

**Feature Branch**: `016-auth-ldap-import`

**Created**: 2026-09-24

**Status**: Draft

**Input**: User description: "use speckit to a new future to the auth service ability to import users from ldap the ldap query must have ability to filter. Imported users are inactive and user with enugh permissions can active each one of them (send invite)"

## Overview

Tenant administrators can connect the auth service to their organisation's LDAP
directory (e.g. Active Directory, OpenLDAP), search it with a filter, preview the
matching people, and import the ones they choose as platform users. Imported
users are **inactive**: they cannot sign in and receive no email. An
administrator with the right permission then **activates** imported users one at
a time (or several selected at once), which sends each of them the platform's
normal invitation; the person accepts it and sets their password and MFA exactly
as an invited user does today.

The directory is used only as a **source of people**. Sign-in stays with the
platform (password + MFA); users do not authenticate against LDAP.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Connect a directory (Priority: P1)

A tenant administrator registers their LDAP directory: server address, secure
connection mode, the service account used to read the directory and its
password, the search base, and which directory attributes hold the email
address, display name and unique identifier. They test the connection before
saving.

**Why this priority**: Nothing can be imported without a working, securely
stored connection.

**Independent Test**: Add a directory connection, run "Test connection" and see
success (or a clear error for a wrong password, unreachable host or untrusted
certificate), save it, and confirm the service-account password is never shown
again.

**Acceptance Scenarios**:

1. **Given** a tenant administrator, **When** they save a connection with valid settings, **Then** it is stored for their tenant only, and the service-account password is stored encrypted and never returned.
2. **Given** connection settings, **When** "Test connection" is run, **Then** the result states success, or which step failed (unreachable server, TLS/certificate problem, wrong credentials, search base not found), without echoing the password.
3. **Given** a connection that is not encrypted (plain LDAP without StartTLS), **When** it is saved, **Then** it is refused unless the platform is running in development mode.
4. **Given** a saved connection, **When** it is edited without re-entering the password, **Then** the stored password is kept; **When** it is deleted, **Then** users already imported from it remain.

---

### User Story 2 - Search the directory with a filter and import selected people (Priority: P1)

The administrator enters an LDAP filter (e.g. `(&(objectClass=person)(department=Engineering))`),
optionally narrows the search base, and previews the matching entries: name,
email, whether each person already exists on the platform. They select some or
all and import them. Imported users appear in the user list as **inactive
(imported)**.

**Why this priority**: This is the core ability requested — filtered import.

**Independent Test**: Run a filtered search, see only matching entries, import a
selection, and see those users listed as inactive with their directory origin;
confirm none of them can sign in and no email was sent.

**Acceptance Scenarios**:

1. **Given** a saved connection, **When** a search runs with a valid LDAP filter and optional base and scope (one level / subtree), **Then** only matching entries are returned (up to a page limit, with a clear notice when more matched), each showing the mapped name and email and a status: new, already a platform user, or already imported.
2. **Given** an invalid filter, **When** it is searched, **Then** it is refused with the parse error before any directory call; **Given** a slow or huge search, **Then** it stops at the time and size limits with a clear message.
3. **Given** selected entries, **When** they are imported, **Then** each new person becomes a user of the tenant with status "imported" (inactive), their directory identifier and connection recorded, and no email is sent.
4. **Given** an entry without an email address, or whose email already belongs to a platform user in the tenant, **When** it is imported, **Then** it is skipped with the reason, and the import reports created / skipped / failed counts.
5. **Given** a person already imported, **When** they are imported again, **Then** their name is refreshed from the directory but no duplicate is created and their status is unchanged.
6. **Given** a search, **Then** the filter the administrator typed is combined with the connection's base filter (if any) so a search can never widen beyond what the connection allows.

---

### User Story 3 - Activate imported users by sending invitations (Priority: P1)

An administrator with the invite permission opens an imported user (or selects
several) and chooses "Activate — send invitation", optionally choosing roles and
groups. Each person receives the standard invitation email; once they accept,
they are an active user.

**Why this priority**: Import is only useful once people can actually be
brought on board; this completes the requested flow.

**Independent Test**: Activate one imported user and see an invitation email
sent and their status change to invited; accept the invitation and sign in;
activate a batch of three and see three invitations.

**Acceptance Scenarios**:

1. **Given** an imported user, **When** an administrator holding the invite permission activates them with optional roles/groups, **Then** a standard invitation is created and emailed, and the user's status becomes "invited".
2. **Given** an invited (formerly imported) user, **When** they accept the invitation and set a password and MFA, **Then** they become active and can sign in; their directory link is kept.
3. **Given** a user without the invite permission, **When** they try to activate, **Then** it is refused; roles they are not allowed to grant cannot be assigned (same rules as normal invitations).
4. **Given** several selected imported users, **When** they are activated together, **Then** each receives their own invitation and the result lists any that failed (e.g. email delivery problem) without affecting the others.
5. **Given** an imported user who should not join, **When** an administrator removes them, **Then** they are deleted without any email being sent.

### Edge Cases

- An imported user's email changes in the directory: a re-import updates it only while the user is still "imported"; after activation the platform email is authoritative.
- A person is removed from the directory: nothing happens automatically (no sync); administrators can see the last import time.
- Two directory entries share an email: the second is skipped as a duplicate.
- The directory returns referrals or enormous attribute values: referrals are not followed; values are truncated/refused at safe limits.
- An imported user tries to sign in or reset their password: refused exactly as for an unknown account (no disclosure that the account exists).
- An invitation for a formerly imported user expires: it can be resent like any invitation.
- The directory is unreachable during a search: a clear error; nothing imported.
- The tenant's user limit (if any) would be exceeded by an import: the import is refused or partially applied with the reason.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST let tenant administrators create, view, edit, test and delete LDAP directory connections for their tenant: server URL (ldaps:// or ldap:// with StartTLS), optional trusted CA certificate, service-account bind DN and password, search base, optional base filter, attribute mapping (unique id, email, display name; defaults per directory type), and time/size limits.
- **FR-002**: The service-account password MUST be stored encrypted, never returned, never logged; editing without a new password keeps the stored one.
- **FR-003**: System MUST let administrators search a connection with an RFC 4515 filter, optional base (inside the connection's base) and scope, validating the filter before calling the directory and combining it with the connection's base filter.
- **FR-004**: Search results MUST show mapped name, email and platform status (new / existing user / already imported), be limited in size and time, and indicate when results were truncated.
- **FR-005**: System MUST import selected entries as tenant users in a new inactive status "imported", recording the connection, directory unique id and import time; no email is sent and the user cannot sign in, reset a password or be looked up as an active user.
- **FR-006**: Import MUST be idempotent (keyed by connection + directory unique id), skip entries without email or with an email already used by another tenant user, and report created / updated / skipped (with reason) / failed.
- **FR-007**: System MUST let a user holding the invite permission activate one or several imported users, optionally with roles and groups, creating and emailing a standard invitation for each and moving the user to "invited"; the existing invitation acceptance flow completes activation.
- **FR-008**: Role and group assignment during activation MUST follow the existing invitation rules (a caller cannot grant roles beyond their own authority).
- **FR-009**: System MUST let administrators delete imported (never-invited) users without notification.
- **FR-010**: The user list MUST show the new status and directory origin, and be filterable by status "imported".
- **FR-011**: System MUST record audit entries for connection changes, connection tests, searches (filter and result count, not the entries), imports (counts and user ids) and activations.
- **FR-012**: Permissions: managing directory connections, searching and importing require a new directory-management permission; activation requires the existing invite permission; both are granted to the tenant administrator role by default.
- **FR-013**: The console MUST provide: a directory connections page (list + drawer with test), an import page (filter input, preview table with selection, import result), and in the user list an "Activate" action for imported users (single and multi-select).

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: auth service → customer LDAP server over the network; browser console → auth API; auth → email relay (invitations).
- **Data classification**: service-account credentials (secret); directory personal data — names, emails, identifiers (PII); audit records (tamper-evident).
- **Authentication/Authorization**: console callers use their platform session with the new directory permission or the invite permission; connections and imported users are tenant-scoped.
- **Threat scenarios**: LDAP filter injection widening a search; credential leakage via responses, logs or error messages; a malicious or spoofed directory server (MITM) feeding false users or capturing the bind password; cross-tenant access to another tenant's connection or imported users; directory used for internal network probing (SSRF) by pointing the URL at internal hosts; oversized or hostile directory responses; account enumeration through imported-but-inactive accounts.
- **SR-001**: Connections MUST use TLS (ldaps or StartTLS) with certificate verification against system roots or the configured CA; plaintext and skip-verify are refused outside development mode.
- **SR-002**: The bind password MUST be encrypted at rest with the service's key-encryption key and never appear in any response, log, audit entry or error text.
- **SR-003**: Search filters MUST be parsed and validated, combined with the connection's base filter by conjunction, and executed only under the connection's base DN; referrals MUST NOT be followed; size and time limits MUST be enforced server-side and client-side.
- **SR-004**: Connection targets MUST be restricted by a platform-level allow/deny policy (e.g. deny loopback and platform-internal service addresses by default) to prevent probing internal services.
- **SR-005**: Connections, searches, imported users and activations MUST be isolated per tenant (row-level security).
- **SR-006**: Imported users MUST behave exactly like non-existent accounts for sign-in, password reset and recovery (no enumeration).
- **SR-007**: Every change and search MUST be audited append-only with actor, tenant, subject and outcome; directory PII is not copied into audit detail beyond user ids and counts.

### Key Entities *(include if feature involves data)*

- **Directory connection**: tenant-owned LDAP source; URL, TLS mode, CA, bind DN, encrypted bind password, search base, base filter, attribute mapping, limits, last test result.
- **User (extended)**: gains status "imported" and a directory link (connection, directory unique id, last imported at).
- **Import run**: who searched/imported what, when, with counts (audit-level record).
- **Invitation (existing)**: reused unchanged for activation.

## Success Criteria *(mandatory)*

- **SC-001**: An administrator can connect a directory, filter it and import 100 selected people in under 5 minutes.
- **SC-002**: 100% of imported users are unable to sign in, reset a password or trigger any email until activated.
- **SC-003**: Activating an imported user results in an invitation email within 1 minute and a usable account after acceptance, in 100% of test cases.
- **SC-004**: Re-importing the same selection creates zero duplicates.
- **SC-005**: No search can return entries outside the connection's base DN and base filter, including with crafted filters (verified by injection tests).
- **SC-006**: The bind password never appears in any response, log, audit entry or error (verified by inspection).
- **SC-007**: A search over a directory of 50,000 entries returns its (limited) preview in under 10 seconds.

## Assumptions

- LDAP is used only to discover people; authentication remains the platform's own password + MFA (no LDAP bind at sign-in).
- Import is on demand; there is no scheduled synchronisation and no automatic deactivation when someone leaves the directory.
- Directory group membership is not mapped to platform roles or groups; roles/groups are chosen at activation.
- Active Directory and OpenLDAP attribute defaults are offered (e.g. objectGUID / entryUUID, mail, displayName / cn); other directories can set the mapping manually.
- The existing invitation email template and expiry rules are reused.

## Out of Scope

- LDAP / Active Directory authentication (sign-in with directory passwords) and SSO.
- Scheduled or continuous sync, automatic deactivation, and group-to-role mapping.
- SCIM provisioning and importing from CSV.
- Writing back to the directory.
