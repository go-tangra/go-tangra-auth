# Contract: admin HTTP API and console (019)

All under `/api/v1`, `roles:manage` (existing `RequireAdmin` + permission
binding), CSRF as the rest of the console API. `api/openapi/console.yaml`
is updated and stays authoritative.

## Permission references

- Qualified: `module:resource:action`, pattern
  `^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9_-]{0,63}:[a-z][a-z0-9_-]{0,31}$`.
- Legacy (until `prune-legacy`): `resource:action`; accepted in a role
  update only if the role already holds it (kept), never newly granted.

## Catalogue

`GET /admin/permissions` → `200 [Permission]`

```json
{
  "ref": "warden:backup:manage",
  "module": "warden",
  "module_display_name": "Warden",
  "resource": "backup",
  "action": "manage",
  "description": "Export and import tenant backups …",
  "grantable": true,
  "legacy": false
}
```

`grantable`: the actor may grant it (owner: all; otherwise the actor holds
it — one `BatchCheck` per 100 permissions). Retired modules' permissions are
omitted. Legacy rows: `module ""`, `module_display_name "Before modules"`,
`legacy true`. Sorted by module display name (`auth` = "Authentication"),
resource, action.

## Roles

`GET /admin/roles` → `200 [Role]`

```json
{
  "id": "…", "slug": "m.warden.viewer", "display_name": "Warden viewer",
  "description": "Read secrets granted to the user",
  "builtin": false,
  "origin": "module",            // builtin | module | custom
  "module": "warden", "module_display_name": "Warden", "module_slug": "viewer",
  "locked": true,                // builtin or module
  "retired": false, "retired_at": null,
  "permissions": ["warden:secrets:read"]
}
```

`GET /roles` (member picker) adds `origin`, `module_display_name`,
`retired` (retired roles are listed but not selectable).

`POST /admin/roles` `{slug, display_name, permissions}` — unchanged shape;
permissions qualified; slugs `owner|admin|member|auditor|operator` and any
slug with a dot → `400 validation_failed`.

`PUT /admin/roles/{id}` → `403 builtin` (built-in) | `403 managed_role`
(module role; body `hint: "clone"`) | `403 self_escalation` |
`400 validation_failed`.

`POST /admin/roles/{id}/remove` → `403 builtin` | `403 managed_role`.

`POST /admin/roles/{id}/clone` `{slug, display_name}` → `201 Role`
(origin `custom`, permissions of the source at clone time; legacy grants of
the source are not copied) | `400 validation_failed` | `403
self_escalation` | `404 not_found` | `409 conflict` (slug taken). Source may
be any role except owner (cloning built-ins admin/member/auditor/operator is
allowed and useful as templates). Audit `role_cloned` `{source, slug}`.

## Assignments

`PUT /admin/users/{id}/roles`, `PUT /admin/groups/{id}/roles`,
`POST /admin/invitations`, imported-user activation: a retired role that the
target does not already hold → `409 role_retired` (whole request refused).
Accepting an invitation drops retired roles (audit `invite_accepted`
details `dropped_roles`).

## Audit events (new)

| Type | Actor | Details |
|---|---|---|
| `module_registered` | service | `module`, `delegate` (gateway or empty), `permissions`, `roles`, `tenants` |
| `module_role_upserted` | service | `module`, `slug`, `permissions` (qualified), `tenants` |
| `module_role_retired` | service / operator (CLI) | `module`, `slug`, `assignments_kept` |
| `role_cloned` | user | `source`, `slug`, `permissions` |
| `permission_migrated` | system | `module`, `role`, `count` |
| `permission_pruned` | operator (CLI) | `count` |

Console reason vocabulary (`console/src/api/vocab.ts`) adds
`managed_role`, `role_retired` and the new event types.

## Console

- **Role editor** (`console/src/views/admin/RoleEditor.vue`): sections per
  module (module display name, sorted; "Authentication" for `auth`), inside
  each module sub-groups per resource; checkbox label `action — description`;
  per-module "Select all" / "Clear" toggling only `grantable` permissions;
  non-grantable permissions disabled with a tooltip ("you do not hold this
  permission"); "Before modules" section for legacy grants (read-only, shown
  only when the role holds any). Module roles open read-only with origin
  banner and a "Clone" action; built-ins as today plus "Clone".
- **Roles list** (`Roles.vue`): origin badge (`built-in` / module display
  name / `custom`), `retired` badge with tooltip "No longer provided by
  <Module>; kept for existing assignments", Clone action (dialog: name,
  slug suggested from the name), Edit/Remove only for custom roles.
- **Pickers** (`RoleGroupPickers.vue`, invite dialog): module roles show
  their module; retired roles are not selectable.
- Schema `console/src/schemas/role.ts`: permission pattern qualified (or
  legacy for kept grants), reserved slugs extended.
