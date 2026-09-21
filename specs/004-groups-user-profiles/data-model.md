# Data Model: User Groups & User Profiles

Extends the feature 002 model (`specs/002-tenant-auth-service/data-model.md`).
Every new table carries `tenant_id` and joins the row-level-security policy set
of migration `0003_rls.sql` (`tenant_isolation` on `tenant_id`); the app role
gets `SELECT/INSERT/UPDATE/DELETE` grants like `role_bindings`.

## New tables (migration `0005_groups_profiles.sql`)

### groups

| column | type | rules |
|--------|------|-------|
| id | uuid PK | UUIDv7 |
| tenant_id | uuid FK tenants | RLS |
| name | text | 1–64 chars after trim, no control chars; unique per tenant case-insensitively: `UNIQUE (tenant_id, lower(name))` |
| description | text default '' | ≤ 500 chars |
| created_by | uuid null | actor |
| created_at, updated_at | timestamptz | |

### group_members

| column | type | rules |
|--------|------|-------|
| group_id | uuid FK groups ON DELETE CASCADE | |
| user_id | uuid FK users ON DELETE CASCADE | same tenant as the group (checked in service; enforced by RLS) |
| tenant_id | uuid | RLS |
| added_by | uuid null | |
| added_at | timestamptz | |
| PK | (group_id, user_id) | re-adding is a no-op (`ON CONFLICT DO NOTHING`) |

Index `group_members (tenant_id, user_id)` for "groups of a user".

### group_roles

| column | type | rules |
|--------|------|-------|
| group_id | uuid FK groups ON DELETE CASCADE | |
| role_id | uuid FK roles ON DELETE CASCADE | deleting a role withdraws it from every group (edge case) |
| tenant_id | uuid | RLS |
| granted_by | uuid null | |
| granted_at | timestamptz | |
| PK | (group_id, role_id) | |

### avatars

| column | type | rules |
|--------|------|-------|
| id | text PK | `sha256` hex of the stored bytes |
| tenant_id | uuid | RLS |
| user_id | uuid FK users ON DELETE CASCADE | one live avatar per user: `UNIQUE (user_id)` |
| content_type | text | always `image/jpeg` in this version |
| bytes | bytea | ≤ 512×512 JPEG q85, typically 20–120 KiB |
| size | integer | |
| created_at | timestamptz | |

Replacing an avatar deletes the previous row in the same transaction; the
old URL then answers `not_found`.

## Changed tables

### users (new columns)

| column | type | rules |
|--------|------|-------|
| first_name | text default '' | 0–100 chars, trimmed, no control chars |
| last_name | text default '' | 0–100 chars, trimmed, no control chars |
| phone | text default '' | '' or E.164 (`^\+[1-9][0-9]{6,14}$`) after normalisation; **PII, never logged** |
| avatar_id | text null FK avatars(id) ON DELETE SET NULL | |
| display_name_explicit | boolean default true | existing rows keep their display name; false once first/last are used to derive it |
| profile_updated_at | timestamptz null | |

`display_name` derivation on profile save when `display_name_explicit = false`:
`trim(first_name || ' ' || last_name)`, else previous `display_name`, else the
email local part.

### invitations (new columns)

| column | type | rules |
|--------|------|-------|
| group_ids | uuid[] default '{}' | validated to exist in the tenant at creation; missing at acceptance are skipped |
| first_name, last_name | text default '' | same rules as users |

### auth_audit_events (new `event_type` values)

`group.created`, `group.updated`, `group.deleted`, `group.member_added`,
`group.member_removed`, `group.role_granted`, `group.role_revoked`,
`profile.updated`, `avatar.updated`, `avatar.removed`. Subject kinds: `group`
(with `details.user_id` / `details.role` where relevant) and `user`. Profile
events carry `details.fields` (names only), never values.

## OpenFGA model changes

```
type group
  relations
    define tenant: [tenant]
    define member: [user]

type role
  relations
    define tenant: [tenant]
    define assignee: [user, group#member]
```

Tuples written by the service (all objects prefixed with the tenant id, see
`internal/authz/objects.go`):

| change | tuple |
|--------|-------|
| create group | `tenant:T tenant group:T/<gid>` |
| add member | `user:U member group:T/<gid>` |
| grant role to group | `group:T/<gid>#member assignee role:T/<slug>` |
| delete group | delete all of the above for the group |

`group:T/<gid>` uses the group id (not the name) so renames are free.

## Derived views (not stored)

### Effective roles with sources

```sql
SELECT r.id, r.slug, 'direct' AS source, NULL::uuid AS group_id, NULL::text AS group_name
  FROM role_bindings b JOIN roles r ON r.id = b.role_id
 WHERE b.tenant_id = $1 AND b.user_id = $2
UNION ALL
SELECT r.id, r.slug, 'group', g.id, g.name
  FROM group_members m JOIN group_roles gr ON gr.group_id = m.group_id
  JOIN roles r ON r.id = gr.role_id JOIN groups g ON g.id = m.group_id
 WHERE m.tenant_id = $1 AND m.user_id = $2
```

`EffectiveRoleSlugs` is `SELECT DISTINCT slug` over the same union; it
replaces `UserRoleSlugs` wherever a session or token is built.

### Session view (Valkey `sess:<hash>`), new fields

| field | purpose |
|-------|---------|
| policy_version | tenant version when `roles` were loaded; drift → reload |
| display_name | for `SessionIdentity` without a DB read |
| avatar_url | `/api/v1/users/<uid>/avatar/<avatar_id>` or '' |

## Entity relationships

```
tenant 1──* group 1──* group_members *──1 user
                  └──* group_roles   *──1 role
user 1──0..1 avatar
invitation *──* group (by id array)
```

## State transitions

- **Group**: created → (renamed/described)* → deleted (hard delete; cascades
  members and roles; FGA tuples removed; audit keeps the record).
- **Avatar**: none → set (row + `users.avatar_id`) → replaced (new row, old
  deleted) → removed (row deleted, `avatar_id` null).
- **User status** interplay: deactivated users keep memberships; `Decider`
  already denies on `user_status != active`; reactivation restores group
  access with no extra step.
