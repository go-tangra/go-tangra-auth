# Feature Specification: Module Roles and Module-Scoped Permissions

**Feature Branch**: `019-module-roles`

**Created**: 2026-09-26

**Status**: Draft

**Input**: User description: "in auth roles i like modules to be able to provide the default roles for example warden module to provide Warden administrator or Warden viewer with attached corresponding permissions. In addition to that on /console/admin/roles/new when permission is displayed to be grouped by module (service)"

**Decisions taken with the user**: module roles are locked (administrators
assign them but cannot change their permissions; they can clone them into an
ordinary role); module roles exist in every tenant, including tenants created
later. Module-scoped permissions are in scope (required for both requests and
to close a cross-module privilege gap).

## Context

Every platform module (warden, notification, ipam, …) registers its
permissions with auth, and administrators build roles from them. Today a
permission is only a resource and an action (`backup:manage`,
`stats:read`), and several modules register the same names: `backup:manage`
is registered by all ten modules, `stats:read` by eight, `permissions:manage`
by four. Granting `backup:manage` therefore grants backup export and import in
every module at once — a role meant for one module silently reaches all of
them. Because permissions carry no module, the role editor cannot group them
by module either.

Modules can only attach permissions to the platform's built-in roles, and two
of the slugs they use (`auditor`, `operator` outside the platform tenant) do
not exist, so those grants are silently lost. Some modules (dns, ticket)
already define their own roles ("dns viewer", "ticket agent") in code, but
nothing sends them to auth.

This feature makes permissions belong to a module, lets each module provide
its own ready-made roles, and groups the role editor by module.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Assign a module's ready-made role (Priority: P1)

An administrator opens Roles and finds, next to the platform roles, the roles
provided by modules: "Warden administrator", "Warden viewer", "Ticket agent",
"DNS viewer", … each with a description and the module it comes from. They
assign "Warden viewer" to a user or a group; that user can now read secrets
granted to them in warden and nothing in other modules.

**Why this priority**: This is the main request: administrators should not
have to assemble roles permission by permission for common needs.

**Independent Test**: With warden running, a new tenant shows "Warden
administrator" and "Warden viewer"; assigning "Warden viewer" to a user gives
exactly the permissions warden declared for it, verified by the user's
effective permissions and by warden allowing reads but refusing writes.

**Acceptance Scenarios**:

1. **Given** a module that declares roles, **When** it registers with auth,
   **Then** those roles appear in every tenant with the module's name,
   display name, description and permissions.
2. **Given** a tenant created after the module registered, **When** the
   tenant is created, **Then** it receives the module's roles as well.
3. **Given** a module role, **When** an administrator assigns it to a user
   or group, **Then** the assignee holds exactly the role's permissions.
4. **Given** a module role, **When** an administrator tries to change its
   permissions, rename it or delete it, **Then** it is refused with a hint
   to clone it.
5. **Given** a module role, **When** an administrator clones it, **Then** an
   ordinary editable role with the same permissions and a new name is created
   (subject to the usual rule that they may only grant what they hold).
6. **Given** a module upgrade that changes a role's permissions, **When** it
   registers again, **Then** every tenant's copy of that role is updated;
   assignments are kept.
7. **Given** a module that no longer declares a role, **When** it registers
   again, **Then** the role is kept for existing assignments but marked
   retired, cannot be newly assigned, and administrators see why.

---

### User Story 2 - Permissions grouped by module in the role editor (Priority: P1)

An administrator creating or editing a role sees the permissions grouped by
module (Warden, Notification, IPAM, …), each group titled with the module's
display name, and inside each module grouped by resource.

**Why this priority**: Explicitly requested; with dozens of permissions from
eleven modules the flat list is hard to use.

**Independent Test**: Open Roles → New role; the permission list shows one
section per registered module, with the module's display name, and the same
action names (e.g. "backup: manage") appear separately under each module.

**Acceptance Scenarios**:

1. **Given** the role editor, **When** it loads, **Then** permissions are
   grouped by module (display name, sorted), then by resource.
2. **Given** two modules that both have a "backup: manage" permission,
   **When** the editor is shown, **Then** each appears in its own module
   group and can be granted independently.
3. **Given** a module group, **When** the administrator uses "select all in
   module", **Then** only that module's permissions they may grant are
   selected.
4. **Given** the auth module's own permissions, **When** the editor is shown,
   **Then** they appear under "Authentication".

---

### User Story 3 - Permissions belong to one module (Priority: P1)

A permission granted for one module has no effect in another. An
administrator who grants "Warden: backup: manage" does not grant IPAM backups.

**Why this priority**: Both requests depend on it, and it closes a
cross-module privilege gap that exists today.

**Independent Test**: A role holding only warden's backup permission can
export warden backups and is refused IPAM backup export.

**Acceptance Scenarios**:

1. **Given** a role with a permission of module A, **When** its holder calls
   a route of module B requiring an action with the same name, **Then** it is
   refused.
2. **Given** existing roles created before this feature, **When** the
   platform is upgraded, **Then** every holder keeps exactly the access they
   had: a role that held `backup:manage` holds each module's backup
   permission afterwards (administrators may then narrow it).
3. **Given** a module and the gateway both registering the same module's
   permissions, **When** registrations interleave, **Then** each permission
   keeps its module identity.

---

### User Story 4 - Built-in role grants are never silently lost (Priority: P2)

Grants modules declare for the platform's built-in roles (owner, admin,
member, auditor, operator) arrive, or the operator sees why not.

**Why this priority**: Today some grants disappear without trace; module
roles make most of those grants unnecessary, but the existing ones must be
correct.

**Independent Test**: A module granting `stats:read` to `auditor` results in
an auditor role holding it in every tenant, or a visible registration
warning if the platform does not provide that role.

**Acceptance Scenarios**:

1. **Given** a grant to a built-in role that does not exist in a tenant,
   **When** a module registers, **Then** the registration answer and the log
   report the skipped role instead of dropping it silently.
2. **Given** the platform's decision on `auditor` and `operator` (see
   Assumptions), **When** tenants are created, **Then** they contain the
   built-in roles module grants may target.

---

### Edge Cases

- Two modules declare a role with the same name: roles are identified by
  module plus slug, so both exist; display names are shown with the module.
- An administrator's custom role has the same name as a new module role:
  both exist; the module role is shown with its module badge.
- A module role references a permission the module did not register: the
  registration is refused for that role and reported.
- A module is removed from the platform: its roles stay (retired) while
  assigned; its permissions stop being offered in the editor.
- An administrator who may not grant all of a module role's permissions
  tries to assign it: refused, like assigning any role today.
- The gateway registers permissions for a module it proxies: it registers
  them under that module, not under itself.
- Very old modules (before this feature) keep registering unscoped
  permissions during the upgrade: they are attributed to the calling module
  and keep working until the module is upgraded.

## Requirements *(mandatory)*

### Functional Requirements

**Module-scoped permissions**

- **FR-001**: Every permission MUST belong to exactly one module; the same
  resource and action in two modules MUST be two independent permissions.
- **FR-002**: Authorization of a module's routes and service calls MUST check
  the permission of that module only.
- **FR-003**: The upgrade MUST preserve effective access: every role, group
  and user holding an unscoped permission before MUST hold the corresponding
  permission of every module that registers it afterwards.
- **FR-004**: The module a permission belongs to MUST be derived from the
  registering module's verified identity (or, for the gateway, from the
  module it registers on behalf of), never from free text.

**Module roles**

- **FR-005**: A module MUST be able to declare roles: identifier, display
  name, description and permissions (its own permissions only).
- **FR-006**: Declared roles MUST exist in every tenant, including tenants
  created later, and be updated in every tenant when the declaration changes.
- **FR-007**: Module roles MUST be assignable to users and groups like any
  role, and MUST NOT be editable, renamable or deletable by administrators.
- **FR-008**: Administrators MUST be able to clone a module role into an
  ordinary role (new name; same permissions; normal escalation rules).
- **FR-009**: A role no longer declared by its module MUST be kept while
  assigned, shown as retired, and refused for new assignments.
- **FR-010**: Role lists MUST show the origin of each role: platform
  (built-in), module (with module name), or custom.

**Role editor**

- **FR-011**: The permission catalogue returned to the console MUST include
  each permission's module identifier and module display name.
- **FR-012**: The role editor MUST group permissions by module (display
  name), then by resource, and offer "select all" per module limited to
  permissions the administrator may grant.

**Built-in roles**

- **FR-013**: Grants to built-in roles that do not exist in a tenant MUST be
  reported, not silently dropped.
- **FR-014**: The platform MUST define which built-in roles exist in which
  tenants so that module grants target existing roles (see Assumptions).

**Compatibility and rollout**

- **FR-015**: auth MUST accept registrations from modules that do not yet
  send module roles or module-scoped data during the upgrade, attributing
  their permissions to the calling module.
- **FR-016**: Each module MUST declare its roles (initial set per module in
  the plan, e.g. warden administrator/viewer, dns administrator/viewer,
  ticket administrator/agent/viewer).

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: module → auth registration over the mesh
  (mTLS identity); gateway → auth decisions; browser → admin API.
- **Data classification**: authorization data (permissions, roles, grants) —
  integrity-critical.
- **Authentication/Authorization**: registration only from mesh-authenticated
  platform services; a module may only declare permissions and roles for
  itself (the gateway only for modules it proxies); admin API requires the
  roles-management permission; assignments keep the escalation check.
- **Threat scenarios**: a module declaring roles or permissions for another
  module; a compromised module granting itself broad permissions through a
  role; cross-module permission bleed (today's gap); loss of access during
  the migration; an administrator escalating by cloning or assigning a module
  role with permissions they do not hold; stale roles granting access after a
  module shrinks its declaration.
- **SR-001**: A registration MUST only create or change permissions and roles
  of the caller's own module (gateway: of the modules it registered).
- **SR-002**: Module roles MUST only contain permissions of their module.
- **SR-003**: Assigning or cloning a module role MUST pass the same
  escalation check as any role.
- **SR-004**: The migration MUST be verifiable: a before/after comparison of
  each principal's effective permissions shows no loss and no gain beyond the
  per-module split.
- **SR-005**: Registration, role creation/update/retirement by modules and
  clone operations MUST be audited.

### Key Entities *(include if feature involves data)*

- **Module**: identifier (from the mesh identity, e.g. `warden`), display
  name (e.g. "Warden"), last registration.
- **Permission** (extended): module, resource, action, description.
- **Role** (extended): origin (platform / module / custom), module, stable
  identifier within the module, display name, description, retired flag.
- **Role grant**: role ↔ permission (unchanged in meaning; permission now
  module-scoped).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After the upgrade, 100 % of users keep the access they had
  (automated before/after comparison of effective permissions).
- **SC-002**: A permission granted for one module is refused in every other
  module in 100 % of tested cross-module cases.
- **SC-003**: An administrator can give someone read access to warden by
  assigning one ready-made role, in under 30 seconds.
- **SC-004**: The role editor shows every registered module as its own group;
  no permission appears outside a module group.
- **SC-005**: No module grant is lost silently: every skipped grant is
  reported at registration.

## Assumptions

- Module identity is the service name in the module's mesh identity
  (`spiffe://<trust domain>/svc/<name>`); display names come from the
  module's manifest (already known to the gateway).
- Permission references in the UI and API become module-qualified
  (e.g. `warden:secrets:read`); existing route declarations in modules keep
  their short form and are qualified by the gateway with the route's module.
- `auditor` and `operator` built-in roles: `operator` stays platform-tenant
  only; `auditor` becomes a built-in role of every tenant (read-only
  statistics and audit), since modules already target it. Final choice
  recorded in the plan.
- Module roles are identified by module + slug; display names may repeat
  across modules.
- The initial module role sets reuse the roles dns and ticket already define,
  plus administrator/viewer pairs for the other modules; exact lists are in
  the plan.
- Rollout order: auth and gateway first (accepting both old and new
  registrations), then modules one by one; nothing breaks while modules are
  on older versions.
