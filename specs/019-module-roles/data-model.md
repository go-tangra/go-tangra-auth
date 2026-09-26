# Data Model: Module Roles and Module-Scoped Permissions (019)

## Migration `internal/store/migrations/0011_module_roles.sql`

```sql
-- +goose Up
-- Platform catalogue (system scope: readable in every scope, written with app.system).
CREATE TABLE modules (
  name          text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
  display_name  text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  registered_at timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  retired_at    timestamptz
);

CREATE TABLE module_permissions (
  module      text NOT NULL REFERENCES modules(name),
  resource    text NOT NULL CHECK (resource ~ '^[a-z][a-z0-9_-]{0,63}$'),
  action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_-]{0,31}$'),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  retired_at  timestamptz,
  PRIMARY KEY (module, resource, action)
);

CREATE TABLE module_role_defs (
  module       text NOT NULL REFERENCES modules(name),
  slug         text NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  description  text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  permissions  text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 200), -- "res:act" of this module
  updated_at   timestamptz NOT NULL DEFAULT now(),
  retired_at   timestamptz,
  PRIMARY KEY (module, slug)
);

-- Per-tenant module state (tenant scope, RLS like permissions).
CREATE TABLE tenant_modules (
  tenant_id           uuid NOT NULL REFERENCES tenants(id),
  module              text NOT NULL REFERENCES modules(name),
  first_registered_at timestamptz NOT NULL DEFAULT now(),
  legacy_migrated_at  timestamptz,           -- D3 marker, set after the tuple write succeeded
  PRIMARY KEY (tenant_id, module)
);

-- Permissions become module-scoped; existing rows are legacy (module = '').
ALTER TABLE permissions ADD COLUMN module text NOT NULL DEFAULT ''
  CHECK (module = '' OR module ~ '^[a-z][a-z0-9-]{0,31}$');
ALTER TABLE permissions DROP CONSTRAINT permissions_pkey,
  ADD PRIMARY KEY (tenant_id, module, resource, action);

ALTER TABLE role_permissions ADD COLUMN module text NOT NULL DEFAULT '';
ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_pkey,
  ADD PRIMARY KEY (role_id, module, resource, action);

-- Roles gain origin and module identity.
ALTER TABLE roles
  ADD COLUMN origin      text NOT NULL DEFAULT 'custom' CHECK (origin IN ('builtin','module','custom')),
  ADD COLUMN module      text,
  ADD COLUMN module_slug text,
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 256),
  ADD COLUMN retired_at  timestamptz;
UPDATE roles SET origin = 'builtin' WHERE builtin;
ALTER TABLE roles DROP CONSTRAINT roles_slug_check,
  ADD CONSTRAINT roles_slug_check CHECK (
    (origin <> 'module' AND slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    OR (origin = 'module' AND slug = 'm.' || module || '.' || module_slug)),
  ADD CONSTRAINT roles_module_identity CHECK (
    (origin = 'module') = (module IS NOT NULL AND module_slug IS NOT NULL)),
  ADD CONSTRAINT roles_builtin_origin CHECK (builtin = (origin = 'builtin'));
CREATE UNIQUE INDEX roles_module_slug ON roles (tenant_id, module, module_slug) WHERE origin = 'module';

-- RLS: tenant_modules gets the tenant_isolation policy (0003 pattern).
-- modules, module_permissions, module_role_defs:
--   ENABLE + FORCE RLS; POLICY catalogue_read FOR SELECT USING (true);
--   POLICY catalogue_write FOR ALL USING/WITH CHECK (current_setting('app.system', true) = 'on').
-- Grants: SELECT, INSERT, UPDATE on the four new tables to auth_app (no DELETE on the catalogue).

-- +goose Down
SELECT 1;
```

Forward-only (platform convention). The auto-generated constraint names
(`permissions_pkey`, `role_permissions_pkey`, `roles_slug_check`) are
asserted by the migration test before the change. The `auditor` role is
**not** created in SQL: `EnsureBuiltinRoles` (start-up) writes rows and
OpenFGA tuples together (D6).

## Entities

### Module (`modules`)
| Field | Rule |
|---|---|
| name | service name from the caller's SPIFFE id (`svc/<name>`); `auth` for auth |
| display_name | from the module registration (`module_display_name`) or the gateway manifest; `auth` → "Authentication" |
| retired_at | set by `authsvc modules retire <name>`; hides permissions, retires roles |

### ModulePermission (`module_permissions`) — catalogue
Upserted by every registration of the module; instantiated into
`permissions` of each tenant (registration, tenant creation).

### ModuleRoleDef (`module_role_defs`)
| Field | Rule |
|---|---|
| module, slug | identity; slug `[a-z0-9-]`, 1–32 |
| display_name | "<Module> <role>" e.g. "Warden viewer" |
| permissions | ⊆ the module's permissions in the same registration (SR-002), 1–200 |
| retired_at | set when a registration with `declares_roles` omits the slug; cleared when declared again |

Limits per registration: ≤ 200 permissions, ≤ 20 roles.

### Permission (extended, tenant scope)
| Field | Rule |
|---|---|
| module | `''` = legacy (pre-019), else module name |
| resource, action | unchanged grammar |
| registered_by | caller SPIFFE id (informational; delegate registrations record the gateway) |

Qualified reference: `module:resource:action`; legacy: `resource:action`.
OpenFGA object: `permission:<tid>/<module>~<res>~<act>` (legacy
`permission:<tid>/<res>~<act>`).

### Role (extended)
| Field | Rule |
|---|---|
| origin | `builtin` (owner, admin, member, auditor; operator in the platform tenant), `module`, `custom` |
| slug | custom/builtin grammar without dots; module roles `m.<module>.<slug>` |
| module, module_slug | set iff origin = module |
| display_name, description | module roles: from the definition (locked) |
| retired_at | module roles only; no new assignments |

Custom slugs reserved: owner, admin, member, auditor, operator.

### RolePermission (extended)
`(role_id, module, resource, action)`; mirror of OpenFGA
`role:<tid>/<slug>#assignee granted permission:<tid>/<module>~<res>~<act>`.

### TenantModule (`tenant_modules`)
One row per module registered in a tenant; `legacy_migrated_at` records the
D3 access-preserving migration.

## State

Module role: `absent` → (declared) → `active` → (not declared in a
registration with `declares_roles`, or module retired) → `retired` →
(declared again) → `active`. Retired: kept with its grants and existing
assignments; refused for new assignments; not editable.

Permission (per tenant): `legacy` (module '') → (module registers scoped,
D3 migrates grants) → `legacy + scoped` → (`prune-legacy`) → `scoped`.

## Valkey keys

| Key | Change |
|---|---|
| auth `dec:<t>:<u>:<perm>@<ver>` | `<perm>` is the qualified ref for scoped checks, bare for legacy |
| gateway `gwdec:<t>:<u>:<module>:<res:act>@<ver>` | module added (portal) |
