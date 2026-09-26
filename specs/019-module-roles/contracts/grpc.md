# Contract: auth SDK gRPC changes (019)

`sdk/api/proto/auth/v1/auth.proto`, released as **`sdk/v4.1.0`** (additive;
old clients keep working, D2). Field numbers continue the existing messages.

## Messages

```proto
message CheckRequest {
  string tenant_id = 1;
  string user_id = 2;
  string resource = 3;
  string action = 4;
  map<string, string> context = 5;
  // Module owning the permission. Empty: the caller's module (services) or
  // the legacy permission (gateway). A service other than the gateway may
  // only name its own module.
  string module = 6;
}

message PermissionRef {
  string resource = 1;
  string action = 2;
  string module = 3; // same rules as CheckRequest.module
}

message RegisterPermissionsRequest {
  repeated PermissionDef permissions = 1;   // ≤ 200
  repeated string tenant_ids = 2;           // empty = every active tenant
  repeated BuiltinGrant builtin_grants = 3; // module-scoped to `module`
  // Module the registration is for. Empty: the caller's service name
  // (gateway without module: legacy rows only). Must equal the caller's
  // service name unless the caller is the gateway.
  string module = 4;
  string module_display_name = 5;           // 1–120 chars; kept when empty
  repeated ModuleRoleDef roles = 6;         // ≤ 20; refused from the gateway
  // true: `roles` is the module's complete role set (absent slugs are
  // retired). false: roles are left unchanged (gateway, old modules).
  bool declares_roles = 7;
}

message ModuleRoleDef {
  string slug = 1;               // ^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$
  string display_name = 2;       // e.g. "Warden viewer"
  string description = 3;       // ≤ 256
  repeated string permissions = 4; // "resource:action" of this request, 1–200
}

message RegisterPermissionsResponse {
  uint32 registered = 1;                    // permissions × tenants (unchanged meaning)
  repeated SkippedGrant skipped_grants = 2;
  repeated RoleError role_errors = 3;       // roles rejected individually
  uint32 roles_upserted = 4;                // definitions created or changed
  repeated string roles_retired = 5;        // slugs retired by this registration
}

message SkippedGrant {
  string role = 1;                    // built-in slug, e.g. "operator"
  uint32 tenants = 2;                 // tenants without that role
  repeated string sample_tenant_ids = 3; // ≤ 5
  string reason = 4;                  // role_missing
}

message RoleError {
  string slug = 1;
  string reason = 2; // invalid_slug | invalid_name | foreign_permission | too_many_permissions | no_permissions | duplicate
}
```

`PermissionDef` and `BuiltinGrant` are unchanged. `CheckResponse.reason`
vocabulary unchanged (`role:<slug>` may now name `m.<module>.<slug>`).

## Semantics

### RegisterPermissions

1. Caller module `C` = service name of the SPIFFE id (`svc/<name>`);
   non-`svc/` identities → `PermissionDenied`.
2. Target module `M` = `module` or `C`.
   - `M ≠ C` and `C` is not the gateway → `PermissionDenied`
     (`module_mismatch`), audited.
   - `C` is the gateway: `roles`, `declares_roles`, `builtin_grants` must be
     empty (`InvalidArgument`); `M = auth` → accepted, no change.
   - `C` is the gateway and `module` empty → legacy upsert (today's
     behaviour, module '').
3. Validation: ≤ 200 permissions, ≤ 20 roles, grammar (D11); grants may
   only name permissions of the request (unchanged); built-in grant roles ∈
   {owner, admin, member, auditor, operator}.
4. Catalogue upsert (`modules`, `module_permissions`, `module_role_defs`;
   retirement when `declares_roles`).
5. Per tenant: permissions, D3 migration (first scoped registration), module
   role instantiation/update/retirement (grants diffed against the mirror),
   built-in grants (module-scoped; legacy mirror while legacy rows exist,
   D2); missing built-in roles → `skipped_grants`.
6. Audit: `module_registered` (once per call), `module_role_upserted` /
   `module_role_retired` (per definition), `permission_migrated` (per
   tenant and role).

Errors: `Unauthenticated` (no service identity), `PermissionDenied`
(module mismatch), `InvalidArgument` (limits, grammar, gateway with roles),
`Unavailable` (store/OpenFGA). A rejected role does not fail the call.

### Check / BatchCheck

| Caller | module | Evaluated object |
|---|---|---|
| gateway | set | `M~res~act`; legacy `res~act` if the scoped permission is unknown in the tenant and the legacy one is known (rollout, research implementation note 2) |
| gateway | empty | legacy `res~act` |
| service `C` | empty or `C` | `C~res~act`; legacy `res~act` if the scoped permission is unknown in the tenant and the legacy one is known |
| service `C` | `M ≠ C` | `PermissionDenied` |

`BatchCheck` refs may mix modules (gateway `/me/abilities`). Unknown
permission → `unknown_permission`.

## SDK helper (`sdk/pkg/authclient/registration.go`)

```go
type ModuleRole struct {
    Slug, DisplayName, Description string
    Permissions []string // "resource:action"
}

type Registration struct {
    Module, DisplayName string
    Permissions   []Permission          // {Resource, Action, Description}
    Roles         []ModuleRole
    BuiltinGrants map[string][]string   // built-in slug → refs
}

func (r Registration) Validate() error                        // limits, grammar, SR-002, grant refs
func (r Registration) Request() *authv1.RegisterPermissionsRequest // declares_roles = true
func (r Registration) Register(ctx context.Context, cc grpc.ClientConnInterface, log *slog.Logger) (*authv1.RegisterPermissionsResponse, error)
```

`Register` validates first, logs every `skipped_grants` entry (warn) and
`role_errors` entry (error), and returns the response. Modules call it at
start and every 5 minutes, replacing their hand-written requests.
