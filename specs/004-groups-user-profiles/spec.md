# Feature Specification: User Groups & User Profiles

**Feature Branch**: `004-groups-user-profiles`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "Extend the authentication service (services/auth) with user groups and user profile properties. Groups: a tenant can define groups; users can be members of one or more groups; RBAC roles/permissions can be assigned to groups as well as directly to users, and a user's effective permissions are the union of their direct roles and the roles of every group they belong to. Group membership and group role assignments are managed by tenant admins through the console and the admin API, are audited, and take effect on the next authorization decision (the gateway and downstream services see the change). User profile properties: every user has First Name, Last Name, Avatar and Phone; users can view and edit their own profile (including uploading/changing the avatar), admins can edit any user's profile, and the profile is exposed to the platform (session identity, gateway /me, the shell header) so modules can show who is signed in."

## Overview

Two additions to the authentication service from feature 002, both scoped
strictly to a tenant:

- **Groups** let a tenant administrator organise people ("Finance",
  "Support L2", "Contractors") and grant access to the whole group at once.
  A group carries roles exactly like a user does; a person's effective access
  is everything granted to them directly plus everything granted to every
  group they belong to. Adding someone to a group or changing a group's roles
  changes what that person may do, immediately, everywhere in the platform
  (the application gateway from feature 003 and every downstream service).
- **Profiles** give every user a first name, last name, avatar and phone
  number, editable by the person themselves and by tenant administrators,
  and visible to the rest of the platform so a module can show who is signed
  in instead of an identifier.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Administrator Grants Access Through Groups (Priority: P1)

A tenant administrator creates a group, adds users to it, and assigns roles to
the group. Every member immediately holds the group's roles in addition to
their own. Removing a member, removing a role from the group, or deleting the
group withdraws that access just as immediately. The administrator can always
see why a user holds a role: directly, or through which group.

**Why this priority**: Group-based access is the reason for the feature; it
turns per-person role juggling into a manageable model for tenants with more
than a handful of users. Without it nothing else here changes how access works.

**Independent Test**: In a tenant with a role "invoices-reader" (permission
`invoices:read`) and a user with no roles, create group "Finance", assign the
role to the group, add the user: the gateway now admits the user's request to
an invoices route and the shell shows the invoices navigation. Remove the user
from the group: the next request is refused and the navigation disappears.

**Acceptance Scenarios**:

1. **Given** an administrator of tenant "acme", **When** they create group
   "Finance" with a description, **Then** the group appears in the tenant's
   group list, is empty, and the creation is audited with the actor.
2. **Given** group "Finance" holding role "invoices-reader" and user Dana with
   no direct roles, **When** the administrator adds Dana to "Finance",
   **Then** Dana's next authorization check for `invoices:read` is allowed,
   Dana's effective roles list "invoices-reader (via Finance)", and the
   membership change is audited.
3. **Given** Dana is a member of "Finance", **When** the administrator removes
   Dana from the group (or removes "invoices-reader" from the group, or
   deletes the group), **Then** Dana's next authorization check for
   `invoices:read` is refused, and the change is audited.
4. **Given** Dana holds "invoices-reader" directly **and** through "Finance",
   **When** she is removed from the group, **Then** she still holds the role
   (direct grants are untouched) and the effective roles show it as direct.
5. **Given** Dana is a member of "Finance" and "Support", **When** her
   effective permissions are computed, **Then** they are the union of her
   direct roles and both groups' roles, with no duplicates.
6. **Given** an administrator of tenant "acme", **When** they try to add a
   user from tenant "globex" to an "acme" group or to see "globex" groups,
   **Then** the request is refused as not found: groups never cross tenants.
7. **Given** a user with the "member" built-in role but no admin rights,
   **When** they try to create a group or change membership, **Then** they
   are refused and the attempt is audited.
8. **Given** a group name that already exists in the tenant (case-insensitive),
   **When** an administrator creates another with that name, **Then** the
   request is refused with a validation error.

---

### User Story 2 - A Person Manages Their Own Profile (Priority: P1)

A signed-in user opens their account page, sees their first name, last name,
phone and avatar, edits them, and uploads a new avatar picture. From then on
the platform shell header, the console, and any module that asks show the
person's name and avatar instead of an identifier.

**Why this priority**: Profiles are what every module needs to greet or
identify a person; the self-service path is the one every user goes through,
so it ships first alongside groups.

**Independent Test**: Sign in as a user with an empty profile; set first name,
last name, phone and upload a picture; the gateway identity endpoint and the
shell header show the new name and picture; sign in from another browser and
the same profile appears.

**Acceptance Scenarios**:

1. **Given** a signed-in user, **When** they open their account page,
   **Then** they see their current first name, last name, phone and avatar
   (or a neutral placeholder when none is set).
2. **Given** a signed-in user, **When** they change first name, last name or
   phone and save, **Then** the new values are stored, shown immediately,
   reflected in the shell header on the next page load (the person's own
   changes bypass the platform's identity cache), and audited without
   recording the phone number itself.
3. **Given** a signed-in user, **When** they upload a picture in an accepted
   image format within the size limit, **Then** it becomes their avatar,
   appears in the header and account page, and the previous picture is no
   longer served.
4. **Given** a signed-in user, **When** they upload a file that is not an
   accepted image, exceeds the size limit, or is not really an image despite
   its name, **Then** the upload is refused with a clear reason and nothing
   changes.
5. **Given** a signed-in user, **When** they remove their avatar, **Then**
   the placeholder is shown again everywhere.
6. **Given** a signed-in user, **When** they enter a phone number that is not
   a valid international number, **Then** the save is refused with a
   validation message and the previous value is kept.
7. **Given** a user in tenant "acme", **When** any module in the platform asks
   who is signed in, **Then** it receives the user's identifier, display
   name (first and last name), and avatar location, but never the phone.
8. **Given** a user in tenant "acme", **When** a user from tenant "globex"
   requests the avatar by its address, **Then** the request is refused as
   not found.

---

### User Story 3 - Administrator Edits Any User's Profile (Priority: P2)

A tenant administrator opens a user in the console, sees and edits the
person's first name, last name, phone and avatar, for example to correct a
misspelt name or to remove an inappropriate picture. The user list shows names
and avatars so people are easy to find.

**Why this priority**: Support and compliance need it, but a tenant can
operate with self-service alone.

**Independent Test**: As an administrator, change a user's name and remove
their avatar; the user sees the change on their next page load; the audit log
names the administrator as the actor and the user as the subject.

**Acceptance Scenarios**:

1. **Given** an administrator, **When** they open a user's detail page,
   **Then** they see the profile fields and can edit them under the same
   validation rules as self-service.
2. **Given** an administrator, **When** they save a change to another user's
   profile, **Then** it is stored, the user sees it within one minute (the
   platform's identity cache window) or immediately on their next sign-in,
   and an audit event records administrator (actor) and user (subject).
3. **Given** an administrator, **When** they search or list users, **Then**
   they can find people by first or last name as well as by email, and the
   list shows name and avatar.
4. **Given** a non-administrator, **When** they try to edit another user's
   profile, **Then** they are refused.

---

### User Story 4 - Invite People Straight Into Groups (Priority: P3)

When inviting a new user, the administrator can pick groups in addition to
roles; the person is a member of those groups the moment they accept, so a new
hire lands with the right access and no follow-up step. The invitation form
also captures first and last name so the profile is populated on acceptance.

**Why this priority**: Convenience on top of stories 1 and 2; the same result
is reachable with two steps without it.

**Independent Test**: Invite a person into group "Finance" with a first and
last name; after acceptance the person holds the group's roles and their
profile shows the names.

**Acceptance Scenarios**:

1. **Given** an administrator inviting a new user, **When** they select groups
   in the invitation, **Then** on acceptance the user is a member of exactly
   those groups and holds their roles.
2. **Given** a group named in an invitation is deleted before acceptance,
   **When** the invitation is accepted, **Then** the user joins the remaining
   groups and the missing one is simply skipped and noted in the audit event.
3. **Given** an invitation carrying first and last name, **When** it is
   accepted, **Then** the user's profile shows those names and the person can
   change them afterwards.

---

### Edge Cases

- A user is added to a group they already belong to: no change, no error, no
  duplicate audit noise beyond a single "no-op" record.
- A group's roles include a role that is later deleted: members lose that
  access at the moment of deletion; the group otherwise stays intact.
- A user is deactivated while a group member: they keep membership (for
  reactivation) but hold no effective permissions while deactivated.
- A tenant is suspended: group and profile changes are refused like every
  other tenant operation.
- Very large groups (thousands of members): adding a role to the group must
  not require touching every member individually in a way a user can observe
  as a delay beyond the success criteria.
- Two administrators change the same group concurrently: last write wins for
  name/description; membership and role changes are individually atomic and
  never lost.
- An avatar upload succeeds but the profile save in the same form fails: the
  avatar change stands; the form reports the field errors.
- An avatar request without a session: refused (avatars are not public).
- Names containing non-Latin scripts, apostrophes, hyphens, or combining
  characters are accepted; control characters and leading/trailing whitespace
  are not.
- The phone field is cleared: allowed; the field is optional.

## Requirements *(mandatory)*

### Functional Requirements

**Groups**

- **FR-001**: Tenant administrators MUST be able to create, rename, describe,
  list, and delete groups within their tenant. Group names are unique within
  a tenant (case-insensitive), 1–64 characters.
- **FR-002**: Tenant administrators MUST be able to add and remove users as
  members of a group; a user may belong to any number of groups. Groups are
  flat (a group cannot contain another group).
- **FR-003**: Tenant administrators MUST be able to assign and unassign roles
  (built-in or custom, from feature 002) to a group.
- **FR-004**: A user's effective roles MUST be the union of their directly
  assigned roles and the roles of every group they belong to; every
  authorization decision (feature 002 "check" and the gateway's decisions of
  feature 003) MUST use effective roles.
- **FR-005**: Changes to group membership or group roles MUST take effect on
  the next authorization decision and the next issued proof of identity, and
  MUST be reflected in the platform shell's navigation and abilities on its
  next refresh, without the user signing in again.
- **FR-006**: The proof of identity and the session identity MUST carry the
  user's effective roles, so downstream services that verify offline see
  group-derived roles like direct ones.
- **FR-007**: Administrators MUST be able to view a user's effective roles
  with their source (direct, or the group(s) that grant them), and a group's
  members and roles.
- **FR-008**: Deleting a group MUST withdraw the access it granted from every
  member and MUST be refused unless the administrator confirms the member
  count (the console shows it; the API requires an explicit confirmation).
- **FR-009**: Every group, membership and group-role change MUST be audited
  with actor, subject (group and user where applicable), tenant, outcome and
  time.
- **FR-010**: Invitations MAY name groups; on acceptance the user joins those
  that still exist.

**Profiles**

- **FR-011**: Every user MUST have a profile with first name (0–100
  characters), last name (0–100 characters), phone (optional, valid
  international format) and avatar (optional image). Existing users start
  with empty fields; the existing display name is kept and, when empty, is
  derived from first and last name.
- **FR-012**: Users MUST be able to view and edit their own profile from the
  console, including uploading, replacing and removing their avatar.
- **FR-013**: Tenant administrators MUST be able to view and edit any user's
  profile in their tenant, including removing the avatar.
- **FR-014**: Avatar uploads MUST accept PNG, JPEG and WebP up to 2 MB, MUST
  verify the file really is an image of that type, MUST store a normalised
  square version of at most 512×512 pixels with metadata stripped, and MUST
  refuse anything else with a clear reason.
- **FR-015**: Avatars MUST be served only to signed-in users of the same
  tenant, with an address that changes whenever the picture changes so
  browsers and the shell can cache them safely.
- **FR-016**: The session identity, the gateway's identity endpoint and the
  platform shell header MUST expose the user's display name (first and last
  name, falling back to the previous display name, then email) and avatar
  address. The phone number MUST NOT be exposed there; it is visible only on
  the person's own account page and to administrators.
- **FR-017**: Administrators MUST be able to search users by first name, last
  name or email, and the user list MUST show name and avatar.
- **FR-018**: Profile changes MUST be audited with actor, subject and the set
  of fields changed, but never the field values.
- **FR-019**: A module MUST be able to look up the display name and avatar of
  other users of the same tenant by identifier (for example to show who
  created a record), never the phone.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public HTTP ingress through the application
  gateway (browser console, module calls to the profile lookup);
  service-to-service channel (gateway and downstream services asking for
  identity and decisions); user-supplied binary files (avatar uploads).
- **Data classification**: PII (first name, last name, phone number, avatar
  image); access-control data (group membership, group roles) whose
  manipulation changes what people may do.
- **Authentication/Authorization**: all endpoints require a tenant-scoped
  session or bearer token; group management and other users' profiles require
  the tenant administrator role; self-service profile requires the session
  owner; profile lookup of others requires membership of the same tenant;
  service callers are identified by their service identity as in feature 002.
- **Threat scenarios**: privilege escalation by a non-admin adding themselves
  to a privileged group; cross-tenant group or avatar access; a malicious
  upload (polyglot file, image decompression bomb, embedded scripts, EXIF
  location data); phone numbers leaking through logs, audit or identity
  endpoints; stale access after removal from a group; enumeration of users
  through the profile lookup.
- **SR-001**: Every group, membership and group-role operation MUST be
  authorised as a tenant-administrator action and refused otherwise; refusals
  MUST be audited.
- **SR-002**: Groups, memberships, profiles and avatars MUST be isolated per
  tenant; cross-tenant references MUST be answered as not found, never as
  forbidden.
- **SR-003**: Uploaded avatars MUST be validated by content, not by name or
  declared type; MUST be size- and dimension-limited before decoding;
  MUST be re-encoded so the stored picture contains only pixel data; and
  MUST be served with a fixed image content type and headers that forbid
  content sniffing and script execution.
- **SR-004**: Phone numbers MUST be redacted from logs, audit events and
  error messages; identity endpoints and proofs MUST never carry them.
- **SR-005**: Withdrawal of group access MUST be effective on the next
  authorization decision; a proof of identity issued before the change MUST
  stop granting the withdrawn roles no later than its own expiry, and
  services that consult the authentication service for decisions MUST see
  the change immediately.
- **SR-006**: The profile lookup for other users MUST answer only for
  identifiers in the caller's tenant, MUST be rate-limited, and MUST return
  the same "not found" for unknown and cross-tenant identifiers.
- **SR-007**: Group and profile endpoints MUST enforce request size limits
  and MUST validate every field (length, character classes, phone format)
  before storage.

### Key Entities

- **Group**: A named set of users within one tenant. Attributes: identifier,
  tenant, name (unique per tenant), description, creation and update time,
  roles, members.
- **Group Membership**: A user's belonging to a group; attributes: group,
  user, added by, added at.
- **Group Role Assignment**: A role granted to a group; attributes: group,
  role, granted by, granted at.
- **Effective Roles**: A derived view: for a user, each role held with its
  sources (direct and/or the groups granting it). Not stored; always
  computed from current data.
- **Profile**: The person-facing attributes of a user: first name, last name,
  phone, avatar reference, updated at. Part of the User entity from feature
  002.
- **Avatar**: A stored, normalised image belonging to one user; attributes:
  content-derived address, content type, size, created at.
- **Invitation** (extended): may now carry groups and first/last name.
- **Audit Event** (extended): new event types for group lifecycle, membership,
  group roles and profile changes.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can create a group, assign a role and add ten
  members in under two minutes through the console.
- **SC-002**: A membership or group-role change is enforced on 100% of
  authorization decisions made more than one second after the change is
  confirmed, and appears in the shell's navigation within five seconds.
- **SC-003**: Authorization decisions for a user in twenty groups complete
  within the same latency budget as for a user with direct roles only
  (no more than 10% slower at the 95th percentile).
- **SC-004**: A user can complete their profile, including an avatar upload,
  in under one minute; the new name and picture appear in the shell header on
  the next page load, 100% of the time; an administrator's edit of another
  user reaches that user within 60 seconds.
- **SC-005**: 100% of malformed, oversized or disguised avatar uploads in the
  security test corpus are refused, and no stored avatar retains metadata.
- **SC-006**: 100% of cross-tenant group, membership, profile and avatar
  requests in the test suite are answered as not found.
- **SC-007**: Zero phone numbers appear in logs, audit records or identity
  responses across the whole test run (automated scan).
- **SC-008**: Every group, membership, group-role and profile change produces
  exactly one audit event with the correct actor and subject.
- **SC-009**: Existing users, roles, sessions and proofs keep working
  unchanged after the upgrade; no user needs to sign in again.

## Assumptions

- Groups are flat; nested groups and group-of-groups are out of scope.
- Groups are managed by tenant administrators (owner/admin built-in roles from
  feature 002); there is no separate "group manager" role in this version.
- Effective roles are carried in the proof of identity as a single list; the
  proof does not distinguish direct from group-derived roles (the console does).
- Phone numbers are stored as entered after normalisation to international
  format; verification by SMS or call is out of scope.
- Avatars are stored by the authentication service itself (no external object
  store) and are small (≤ 512×512 after normalisation); animated images are
  stored as their first frame.
- The gateway (feature 003) shell shows the display name and avatar from the
  identity endpoint; it needs no new permission to do so.
- Display name remains for backwards compatibility and becomes "First Last"
  when both are set and the display name was never set explicitly.
- Platform operators manage tenants only and do not edit profiles or groups
  inside tenants (unchanged from feature 002).
- Directory synchronisation (SCIM, LDAP) is out of scope; groups are managed
  by hand or through the admin API.
