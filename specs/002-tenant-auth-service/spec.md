# Feature Specification: Multi-Tenant Authentication & Authorization Service

**Feature Branch**: `002-tenant-auth-service`

**Created**: 2026-09-15

**Status**: Draft

**Input**: User description: "Create a new service for user authentication and authorization built on go-freya. Place the service in the services/ directory (it will later be moved to a separate repository). The service has a frontend using Vue and Vuetify. The system must be designed for multi-tenant support."

## Overview

A standalone service that lets organisations ("tenants") manage their people and
what those people may do, and lets every other service in the platform trust who an
end user is and what they are permitted to do. It is built on the secure
service-to-service channel from feature 001, so other services reach it over
mutually authenticated connections; end users reach it through a web console.

Two audiences: **end users** (sign in, manage their own account, security settings)
and **tenant administrators** (manage users, roles, permissions, sessions and
security policy for their tenant). A **platform operator** creates and suspends
tenants. Everything a tenant sees or changes is strictly scoped to that tenant.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sign In and Obtain Proof of Identity (Priority: P1)

An end user opens the web console (or a client application redirects them to it),
identifies their tenant, signs in with their credentials, and receives a proof of
identity that other services in the platform accept. Signing in is fast, errors are
clear but never reveal whether an account exists, and the session expires on a
schedule the tenant controls.

**Why this priority**: Without sign-in and a verifiable proof of identity nothing
else in the platform can identify a person. This is the minimum viable product.

**Independent Test**: Create a tenant with one user; the user signs in through the
console and calls a demo downstream service with the issued proof; the downstream
service confirms the user's identity and tenant. A wrong password, a locked account,
and an expired proof are each refused with the expected outcome.

**Acceptance Scenarios**:

1. **Given** an active user in tenant "acme", **When** they enter their tenant, email
   and correct password, **Then** they are signed in, see the console home, and hold
   a proof of identity that names the user, the tenant, and its expiry.
2. **Given** any sign-in attempt, **When** the email is unknown **or** the password is
   wrong, **Then** the user sees the same generic failure message and the attempt is
   recorded.
3. **Given** a user in tenant "acme", **When** they attempt to sign in against tenant
   "globex" with the same email and password, **Then** they are refused: identities
   never cross tenants.
4. **Given** a signed-in user, **When** the tenant's session lifetime elapses,
   **Then** the proof stops being accepted by every service and the console asks the
   user to sign in again.
5. **Given** a signed-in user, **When** they sign out, **Then** the session is ended
   immediately everywhere the proof was being used.
6. **Given** a downstream service holding a proof, **When** it validates the proof,
   **Then** it can do so without contacting the authentication service for every
   request, and learns the user, tenant, roles and expiry.

---

### User Story 2 - Tenant Administrator Manages Users and Access (Priority: P1)

A tenant administrator invites people to the tenant, assigns and revokes roles,
deactivates users, forces sign-out, and sees an audit trail of security events —
all within the console, and only for their own tenant.

**Why this priority**: Sign-in is useless without a way to put users in a tenant and
decide what they may do. Together with Story 1 this is the smallest usable service.

**Independent Test**: An administrator of "acme" invites a user, assigns the
"editor" role, later revokes it and deactivates the account; each step is reflected
in the user's next sign-in/authorization outcome and in the audit trail. An
administrator of "globex" cannot see or change anything in "acme".

**Acceptance Scenarios**:

1. **Given** an administrator, **When** they invite someone by email, **Then** the
   invitee receives a one-time, time-limited invitation, sets their own password,
   and appears as an active user of that tenant only.
2. **Given** an administrator, **When** they assign a role to a user, **Then** the
   user's next proof of identity carries that role and downstream authorization
   decisions reflect it.
3. **Given** an administrator, **When** they deactivate a user or force sign-out,
   **Then** the user's existing sessions stop working within seconds and new sign-ins
   are refused until reactivated.
4. **Given** an administrator of tenant A, **When** they try to view or change any
   user, role or setting of tenant B (including by guessing identifiers), **Then** the
   request is refused and recorded.
5. **Given** an administrator, **When** they view the audit trail, **Then** they see
   who did what, when, from where, for their tenant only, and can filter by user and
   event type.

---

### User Story 3 - Fine-Grained Authorization Decisions (Priority: P2)

Tenant administrators define roles as bundles of permissions over the tenant's
resources; application services ask "may user U perform action A on resource R?"
and get a fast, consistent yes/no with the reason. Every tenant has sensible default
roles (owner, administrator, member) and can add its own.

**Why this priority**: Roles in the proof of identity cover coarse decisions;
services with their own resources need a per-action check that stays consistent
with the tenant's role definitions.

**Independent Test**: Define a custom role "auditor" with read-only permissions in
one tenant; a user with that role is allowed to read and refused to write by the
decision endpoint; a user in another tenant with a same-named role is unaffected.

**Acceptance Scenarios**:

1. **Given** a role with permission "invoices:read", **When** a service asks whether
   a user holding that role may "invoices:read", **Then** the answer is allow with
   the role named as the reason.
2. **Given** the same user, **When** the service asks about "invoices:write", **Then**
   the answer is deny with reason "no permission".
3. **Given** an administrator changes a role's permissions, **When** the next decision
   is requested, **Then** it reflects the change within seconds without restarting
   any service.
4. **Given** a deactivated user, **When** any decision is requested, **Then** the
   answer is deny regardless of roles.
5. **Given** a permission that only "owner" holds, **When** an administrator tries to
   grant themselves that permission, **Then** they are refused (no self-escalation).

---

### User Story 4 - Self-Service Account Security (Priority: P2)

An end user manages their own account: changes their password, enables a second
factor (authenticator app), reviews and revokes their active sessions, and recovers
access when they forget their password — without help from an administrator.

**Why this priority**: Reduces administrator load and raises account security; the
service is usable before it exists, so it follows the two P1 stories.

**Independent Test**: A user enables a second factor and must present it on the next
sign-in; a user who forgets their password completes the recovery flow using the
emailed one-time link; a user revokes one of two sessions and only that one stops
working.

**Acceptance Scenarios**:

1. **Given** a signed-in user, **When** they change their password, **Then** the old
   password stops working and all *other* sessions are ended.
2. **Given** a user who enabled a second factor, **When** they sign in with the
   correct password only, **Then** they are asked for the second factor and cannot
   proceed without it; recovery codes work exactly once each.
3. **Given** a user who requests password recovery, **When** they use the emailed
   one-time link within its validity window, **Then** they can set a new password;
   the link cannot be reused and the request does not reveal whether the email exists.
4. **Given** a user with several active sessions, **When** they revoke one, **Then**
   only that session ends.
5. **Given** a tenant policy that requires a second factor, **When** a user without
   one signs in, **Then** they must enrol before reaching the console.

---

### User Story 5 - Platform Operator Manages Tenants (Priority: P3)

A platform operator creates a tenant (name, identifier, first owner), suspends or
reactivates it, and sets platform-wide limits. Suspending a tenant immediately stops
all sign-ins and invalidates all sessions for that tenant.

**Why this priority**: Needed to onboard organisations, but a single default tenant
is enough to deliver Stories 1–4.

**Independent Test**: Create tenant "globex" with an owner; the owner signs in and
invites a user; suspend "globex"; both users are signed out and refused; reactivate;
they sign in again.

**Acceptance Scenarios**:

1. **Given** an operator, **When** they create a tenant with an owner email, **Then**
   the owner receives an invitation and, on acceptance, holds the "owner" role in
   that tenant only.
2. **Given** an operator, **When** they suspend a tenant, **Then** every session of
   that tenant ends within seconds and sign-in is refused with a "tenant suspended"
   message.
3. **Given** a tenant administrator, **When** they try to use operator functions,
   **Then** they are refused.

---

### Edge Cases

- **Brute force**: Repeated failed sign-ins for one account or from one origin are
  slowed down and, past a tenant-configurable threshold, the account is temporarily
  locked; the user is told the account is locked without confirming the password was
  right or wrong.
- **Enumeration**: Sign-in, invitation, and recovery flows respond identically for
  existing and non-existing accounts.
- **Last owner**: The last owner of a tenant cannot be deactivated, demoted, or
  deleted; a tenant always has at least one owner.
- **Identifier collisions**: The same email may exist in several tenants as distinct
  accounts; user identifiers are globally unique and opaque.
- **Clock skew**: Proofs of identity remain valid across a small clock difference
  between services; beyond it they are refused as expired/not-yet-valid.
- **Key rotation**: The keys used to sign proofs rotate on a schedule; proofs signed
  by a recently retired key remain verifiable until they expire, and downstream
  services pick up new keys without restart.
- **Revocation propagation**: Force sign-out, deactivation and tenant suspension take
  effect at every downstream service within a bounded delay even though services
  validate proofs locally.
- **Invitation expiry**: An expired or already-used invitation shows a clear message
  and offers to request a new one; nothing is created until acceptance.
- **Console offline**: If the service is unreachable the console shows a clear
  outage message rather than a blank page or a misleading "wrong password".

## Requirements *(mandatory)*

### Functional Requirements

**Tenancy**

- **FR-001**: Every user, role, permission, session, invitation, policy and audit
  record MUST belong to exactly one tenant, and every read or write MUST be scoped to
  the caller's tenant; cross-tenant access MUST be refused and recorded.
- **FR-002**: Tenants MUST be identifiable by a stable opaque identifier and a
  human-readable unique slug; the console MUST let a user identify their tenant
  before sign-in (by slug, or by a tenant-specific address).
- **FR-003**: A platform operator role MUST exist that can create, suspend,
  reactivate and list tenants, and cannot act *inside* a tenant except through an
  explicit, audited "operator access" flow.
- **FR-004**: Suspending a tenant MUST end all of its sessions and refuse all of its
  sign-ins until reactivated.
- **FR-005**: Each tenant MUST have its own security policy: session lifetime,
  idle timeout, password rules, second-factor requirement, and lockout threshold,
  with secure platform defaults.

**Authentication**

- **FR-006**: Users MUST be able to sign in with tenant + email + password, and,
  when enabled or required, a time-based one-time code from an authenticator app,
  with single-use recovery codes as fallback.
- **FR-007**: Passwords MUST be stored only as a strong one-way hash; the plaintext
  MUST never be logged, stored or returned.
- **FR-008**: Sign-in, recovery and invitation responses MUST NOT reveal whether an
  account exists; failed attempts MUST be rate-limited per account and per origin
  and MUST trigger a temporary lockout past the tenant's threshold.
- **FR-009**: On successful sign-in the service MUST issue a proof of identity
  containing at least: user identifier, tenant identifier, roles, issue and expiry
  time, and a session identifier; downstream services MUST be able to verify it
  offline using published verification keys.
- **FR-010**: Verification keys MUST rotate on a schedule; retired keys MUST remain
  published until every proof signed with them has expired.
- **FR-011**: Sessions MUST be individually revocable (sign-out, admin force sign-out,
  password change, deactivation, tenant suspension) and revocation MUST reach
  downstream services within a bounded delay even though verification is offline.
- **FR-012**: Users MUST be able to change their password, enrol and remove a second
  factor, regenerate recovery codes, and list and revoke their sessions.
- **FR-013**: Password recovery MUST use a single-use, time-limited link delivered
  to the account's email; it MUST NOT reveal whether the email exists.

**Authorization**

- **FR-014**: Each tenant MUST have built-in roles (owner, administrator, member)
  and MUST be able to define custom roles as named sets of permissions.
- **FR-015**: Permissions MUST be strings of the form `resource:action`; services
  MUST be able to register the resources and actions they expose so administrators
  can pick from them.
- **FR-016**: The service MUST answer authorization questions of the form
  "may user U perform action A on resource R (in tenant T)?" with allow/deny and a
  reason, consistently with the tenant's current roles, for active users only.
- **FR-017**: Role and permission changes MUST take effect for subsequent
  decisions and subsequently issued proofs within seconds, without restarts.
- **FR-018**: No user MUST be able to grant themselves a permission they do not
  hold; the last owner of a tenant MUST NOT be removable.

**Administration & Audit**

- **FR-019**: Administrators MUST be able to invite users by email (single-use,
  time-limited invitation), assign and revoke roles, deactivate/reactivate users, and
  force sign-out, for their tenant only.
- **FR-020**: Every security-relevant event (sign-in success/failure, lockout,
  second-factor changes, password change/recovery, role/permission changes,
  invitations, deactivations, session revocations, tenant lifecycle, operator
  access) MUST be recorded with actor, subject, tenant, time, origin and outcome,
  and MUST be viewable and filterable per tenant in the console.
- **FR-021**: The console MUST be usable by end users, tenant administrators and
  operators, showing each only the functions their role allows, and MUST meet
  common accessibility expectations (keyboard navigation, screen-reader labels,
  sufficient contrast).

**Integration**

- **FR-022**: Other platform services MUST reach this service only over the
  platform's mutually authenticated service channel; the console reaches it over
  standard encrypted web transport.
- **FR-023**: The service MUST expose a documented way for client applications to
  send a user to sign in and receive the proof of identity back, and for services
  to look up verification keys and request authorization decisions.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public web (browser ↔ console ↔ service); service ↔
  service (platform channel); service ↔ email delivery; service ↔ data store;
  operator ↔ tenant boundary; tenant ↔ tenant boundary.
- **Data classification**: credentials and second-factor secrets (secret; never
  logged or exported); proofs of identity and session identifiers (secret while
  valid); PII (name, email, sign-in origin); tenant configuration (internal);
  verification keys (public).
- **Authentication/Authorization**: end users by password + optional/required second
  factor; services by platform service identity; operators by a dedicated operator
  tenant with mandatory second factor; every request authorized against the caller's
  tenant and role.
- **Threat scenarios**: credential stuffing and brute force; account enumeration;
  cross-tenant data access via forged or guessed identifiers; proof forgery or
  replay; stolen session reuse after revocation; privilege escalation by
  administrators; invitation/recovery link interception or reuse; key compromise;
  secrets in logs; XSS/CSRF against the console; operator abuse.
- **SR-001**: System MUST enforce tenant scoping on every data access path, not only
  in the user interface.
- **SR-002**: System MUST never log, store in plaintext, or return passwords,
  second-factor secrets, recovery codes, session secrets or signing keys.
- **SR-003**: Proofs of identity MUST be unforgeable without the private signing key
  and MUST be bound to a tenant, a user and an expiry; replay after revocation MUST
  be detected within the bounded delay.
- **SR-004**: All secrets at rest (second-factor seeds, signing keys) MUST be
  encrypted with keys held outside the data store.
- **SR-005**: The console MUST be protected against cross-site request forgery and
  script injection, and MUST set strict browser security headers.
- **SR-006**: Operator actions inside a tenant MUST require an explicit, audited,
  time-limited access grant.
- **SR-007**: Failed authentication and authorization MUST return generic errors to
  the caller; detailed reasons go only to the audit trail.

### Key Entities

- **Tenant**: An organisation using the platform. Attributes: identifier, slug,
  display name, status (active/suspended), security policy, creation time.
- **User**: A person's account within one tenant. Attributes: identifier, tenant,
  email (unique within the tenant), display name, status
  (invited/active/deactivated/locked), password hash, second-factor state, roles.
- **Role**: A named set of permissions within a tenant; built-in or custom.
- **Permission**: `resource:action` registered by a service (e.g. `invoices:read`).
- **Session**: One signed-in instance of a user: identifier, user, tenant, created,
  last seen, expiry, origin, revocation state.
- **Proof of Identity**: A signed, time-limited statement of user, tenant, roles and
  session, verifiable offline with published keys.
- **Invitation**: Single-use, time-limited offer to join a tenant with given roles.
- **Recovery Request**: Single-use, time-limited password-reset grant.
- **Security Policy**: Per-tenant settings (session lifetime, idle timeout, password
  rules, second-factor requirement, lockout threshold).
- **Audit Event**: Actor, subject, tenant, type, time, origin, outcome, details.
- **Signing Key**: Key pair used to sign proofs; identifier, validity, state
  (active/retired).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user completes invitation acceptance and first sign-in in under
  2 minutes; a returning user signs in (password + second factor) in under 30
  seconds.
- **SC-002**: 100 % of cross-tenant access attempts in the test matrix (guessed
  identifiers, tokens from another tenant, administrator of another tenant) are
  refused and audited.
- **SC-003**: Revocation (sign-out, force sign-out, deactivation, tenant suspension)
  is effective at every downstream service within 10 seconds.
- **SC-004**: Downstream services verify proofs of identity offline; at least 99 % of
  verifications need no call to the authentication service.
- **SC-005**: Authorization decisions are answered in under 20 ms at the 95th
  percentile with 1,000 concurrent requests, and reflect role changes within 5
  seconds.
- **SC-006**: Password/second-factor/recovery flows never disclose account
  existence: response content and timing differ by less than 10 % between existing
  and non-existing accounts.
- **SC-007**: Signing keys rotate without any failed verification during rotation
  (0 errors over 3 consecutive rotations under load).
- **SC-008**: Every event type in FR-020 produces exactly one audit record, and the
  console lets an administrator find any event of their tenant by user and type in
  under 30 seconds.
- **SC-009**: The console passes an accessibility audit at the commonly expected
  level (all critical screens keyboard-navigable, labelled, contrast-compliant).
- **SC-010**: The service supports at least 1,000 tenants and 100,000 users with no
  degradation of SC-001/SC-005 targets.

## Assumptions

- **Tenant membership model**: One account per tenant. A user account belongs to
  exactly one tenant; the same email may exist as separate, unlinked accounts in
  several tenants; there is no tenant switching. The user identifies the tenant
  (slug or tenant-specific address) before signing in, and every proof of identity
  is bound to exactly one tenant.
- **External identity providers**: Out of scope. All credentials are managed by this
  service: password plus optional or tenant-required authenticator-app second factor.
  Corporate SSO and social login are not planned for this feature; the per-tenant
  security policy is the natural place to add them later.
- **Proof of identity format**: Proofs are signed, time-limited bearer tokens with
  short lifetime (default 15 minutes) refreshed from a longer-lived session (default 8
  hours, tenant-configurable); revocation reaches services through a short-lived,
  periodically refreshed revocation list plus the proof's short lifetime.
- **Email delivery**: Invitations and recovery links are sent through an existing
  transactional email capability; the service treats delivery as best-effort and
  lets administrators resend.
- **Default tenant**: A "platform" tenant hosting operators is created at first
  start; operator accounts require a second factor.
- **Consent/legal**: Terms acceptance, privacy consent and data-export/erasure flows
  are out of scope for this feature.
- **Location**: The service lives under `services/auth` in this repository for now
  and is written so it can be moved to its own repository without changes to its
  contracts.
- **Constitution alignment**: Governed by constitution v1.0.0 (secure by default,
  zero trust between services, test-first with negative security tests, audit and
  redaction, minimal dependencies); planning MUST include a STRIDE threat model.
