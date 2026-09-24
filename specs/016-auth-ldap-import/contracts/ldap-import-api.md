# Phase 1 Contracts: LDAP User Import (services/auth)

Surfaces: (A) new and changed routes in auth's browser API
(`services/auth/api/openapi/console.yaml`, served on the edge listener or via
the gateway in gateway mode, all declared `Public: true` at the gateway by
`pkg/authmanifest` — auth authenticates with its own `__Host-session` cookie
and authorizes per tenant itself); (B) manifest additions; (C) internal Go
interfaces with fakes; (D) audit vocabulary. No gRPC or event-bus changes.

## A. Console HTTP API (additions to console.yaml, `info.version` → 1.2.0)

Conventions (from console.yaml): every state-changing request carries the
`X-CSRF-Token` header parameter (`#/components/parameters/csrf`); request
bodies are `additionalProperties: false`; errors are `{"reason": "<closed
vocabulary>"}`; ids from another tenant behave as `404 not_found` after a
`cross_tenant_refused` audit; body limit is the default 1 MiB unless noted.

Gates: **D** = `directory:manage` (`RequirePermission`: owner/admin role or an
FGA grant of `directory:manage`); **I** = the existing invitation gate
(`RequireAdmin`, manifest `users:manage`), identical to
`POST /api/v1/admin/invitations`.

Error reasons (closed vocabulary, research D9): `validation_failed`,
`invalid_filter`, `invalid_base`, `invalid_url`, `insecure_transport`,
`invalid_ca`, `target_refused`, `unreachable`, `timeout`, `tls_failed`,
`invalid_credentials`, `base_not_found`, `directory_error`, `not_found`,
`duplicate`, `invalid_state`, `self_escalation`, `rate_limited`, `forbidden`,
`unauthenticated`, `limit_reached`.

### Schemas
```yaml
DirectoryConnection:            # response — NO password field of any kind except the flag
  id: uuid
  name: string
  kind: enum [active_directory, openldap, other]
  url: string
  tls_mode: enum [ldaps, starttls, plain]
  allow_tls12: boolean
  ca_pem_set: boolean           # the PEM itself is returned only by GET /{id} (it is public data)
  bind_dn: string
  bind_password_set: boolean    # always true for stored connections
  base_dn: string
  base_filter: string           # canonical form
  attributes: { uid: string, email: string, display_name: string, first_name: string, last_name: string }
  size_limit: integer           # 1..1000
  time_limit_seconds: integer   # 1..60
  last_test: { at: date-time, outcome: string } | null
  created_at: date-time
  updated_at: date-time

DirectoryConnectionInput:       # create (all required except optional ones) / update (partial)
  name: string (1..80)
  kind: enum [active_directory, openldap, other]
  url: string (≤ 512)
  tls_mode: enum [ldaps, starttls, plain]
  allow_tls12?: boolean
  ca_pem?: string (≤ 65536)     # "" clears
  bind_dn: string (≤ 1024)
  bind_password?: string (1..1024, writeOnly)   # required on create; omitted on update = keep
  base_dn: string (≤ 1024)
  base_filter?: string (≤ 4096)
  attributes?: { uid?, email?, display_name?, first_name?, last_name? }   # defaults from kind
  size_limit?: integer
  time_limit_seconds?: integer

TestResult:
  ok: boolean
  step: enum [connect, tls, bind, search_base] | null   # failing step
  reason: string | null                                  # closed vocabulary; never server text
  tls: { version: string, peer_subject: string } | null  # on success
  duration_ms: integer

SearchRequest:
  filter?: string (≤ 4096)      # RFC 4515; empty = (objectClass=*)
  base?: string (≤ 1024)        # must be within the connection base_dn
  scope?: enum [one, sub]       # default sub

SearchResult:
  items: [ { uid: string, dn: string, email: string|null, display_name: string,
             first_name: string, last_name: string,
             status: enum [new, existing_user, imported, invalid],
             user_id: uuid|null,          # for existing_user / imported
             reason: string|null } ]      # for invalid: no_email | invalid_email | value_too_long | multi_valued_uid
  truncated: boolean              # size/time limit hit
  out_of_scope: integer           # entries dropped because their DN left the base (D6)
  effective_filter: string        # canonical (&<base_filter><filter>) actually sent

ImportRequest:
  uids: [string] (1..500, unique)

ImportResult:
  created: [ { uid, user_id } ]
  updated: [ { uid, user_id } ]
  skipped: [ { uid, reason } ]    # no_email | invalid_email | email_in_use | duplicate_email | already_active | not_found_in_directory | value_too_long
  failed:  [ { uid, reason } ]    # directory_error | timeout | internal

ActivateRequest:
  user_ids: [uuid] (1..100, unique)
  role_ids?: [uuid]
  group_ids?: [uuid] (≤ 50)

ActivateResult:
  items: [ { user_id, outcome: enum [invited, failed], invitation_id: uuid|null, reason: string|null } ]
```

### Directory connections (gate D)
| Method & path | Body | Success | Notable errors |
|---|---|---|---|
| `GET /api/v1/admin/directories` | — | `200 {items: DirectoryConnection[]}` | 403 |
| `POST /api/v1/admin/directories` | DirectoryConnectionInput | `201 DirectoryConnection` | 400 `validation_failed`/`invalid_url`/`invalid_filter`/`invalid_ca`/`insecure_transport`; 409 `duplicate`; 422 `target_refused` (IP-literal host or port outside policy); 409 `limit_reached` |
| `GET /api/v1/admin/directories/{id}` | — | `200 DirectoryConnection` + `ca_pem` | 404 |
| `PUT /api/v1/admin/directories/{id}` | partial DirectoryConnectionInput | `200 DirectoryConnection` | as create; 404 |
| `POST /api/v1/admin/directories/{id}/remove` | — | `204` (imported users stay; links keep `connection_name`) | 404 |
| `POST /api/v1/admin/directories/test` | DirectoryConnectionInput + optional `connection_id` (reuse stored password when `bind_password` omitted) | `200 TestResult` (`ok:false` is still 200) | 400 validation; 429 `rate_limited` |
| `POST /api/v1/admin/directories/{id}/test` | — | `200 TestResult`; persists `last_test` | 404; 429 |
| `POST /api/v1/admin/directories/{id}/search` | SearchRequest | `200 SearchResult` | 400 `invalid_filter` (message = parser position, before any network call) / `invalid_base`; 502 `unreachable`/`tls_failed`/`invalid_credentials`/`directory_error`; 504 `timeout`; 429 |
| `POST /api/v1/admin/directories/{id}/import` | ImportRequest | `200 ImportResult` (partial success) | 400; 502/504 when the directory cannot be reached at all (nothing imported) |

### Users (changed / new)
| Method & path | Gate | Change |
|---|---|---|
| `GET /api/v1/admin/users?status=imported` | admin (unchanged) | `User.status` enum adds `imported`; items gain `directory: {connection_id: uuid|null, connection_name, directory_uid, last_imported_at} \| null` and `invitation_id: uuid \| null` (pending invitation for `invited` users, enables resend) |
| `POST /api/v1/admin/users/activate` | **I** | ActivateRequest → `200 ActivateResult`; per-user `failed` reasons: `invalid_state` (not imported), `not_found`, `internal`; whole-request 403 `self_escalation` when a role/group grants more than the actor holds (checked once, before any invitation) |
| `POST /api/v1/admin/users/{id}/remove-imported` | **I** | `204`; 409 `invalid_state` unless `status = imported`; no e-mail |
| `POST /api/v1/admin/users/{id}/deactivate` / `reactivate` | admin (unchanged) | 409 `invalid_state` for `imported` users (new refusal) |
| `PUT /api/v1/admin/users/{id}/roles` | admin (unchanged) | 409 `invalid_state` for `imported` users |
| `POST /api/v1/admin/invitations` | admin (unchanged) | an `imported` e-mail becomes an activation (still `202 {queued:true}`, identical body); roles now pass the escalation check (403 `self_escalation`) — research D11 |
| `POST /api/v1/signin`, `/api/v1/recovery/*`, `/api/v1/invitations/accept` | public (unchanged) | imported accounts behave exactly as non-existent (same status, body, timing class, no lockout) |

## B. Manifest (`services/auth/pkg/authmanifest/manifest.go`)
- `Permissions` += `{Resource: "directory", Action: "manage", Description:
  "Connect LDAP directories, search them and import users as inactive"}`.
- `Grants`: `owner`, `admin`, `operator` += `directory:manage`.
- `Abilities` += `{Action: [manage], Subject: [DirectoryConnection], Requires:
  "directory:manage"}`.
- `Nav` += `{Title: "Directories", Path: "/console/admin/directories", Icon:
  "mdi-folder-account-outline", Order: 802, Requires: "directory:manage"}`.
- `Version` → `1.2.0`. Routes are derived from console.yaml automatically.

## C. Internal interfaces (with fakes — tests run offline)

```go
// package ldapdir — the LDAP boundary (100 % coverage gate)

// TargetPolicy decides whether a resolved address may be dialled (research D5).
type TargetPolicy struct { /* always-deny set, DenyCIDRs, AllowCIDRs, AllowedPorts */ }
func NewTargetPolicy(cfg config.DirectoryTargets) (*TargetPolicy, error)
func (p *TargetPolicy) CheckURL(raw string) (Endpoint, error)       // save-time: scheme/host/port/literal IP
func (p *TargetPolicy) Control(network, address string, _ syscall.RawConn) error // net.Dialer.Control

// Filters and DNs (research D6).
func CompileUserFilter(s string) (Filter, error)                    // validate + canonicalise
func Combine(base, user Filter) (Filter, error)                     // (&base user), re-compiled
func ScopeBase(connBase, requested string) (string, error)          // requested within connBase
func WithinBase(connBase, entryDN string) bool

// Mapping (research D7/D8).
type Mapping struct{ UID, Email, DisplayName, FirstName, LastName string }
func DefaultMapping(kind string) Mapping
func Decode(m Mapping, e RawEntry) (Person, error)                 // GUID decode, caps, email norm

// Directory is the network side; the real one wraps go-ldap, the fake is in-memory.
type Directory interface {
    Open(ctx context.Context, c ConnParams) (Session, error)        // dial (policy dialer) + TLS/StartTLS
}
type Session interface {
    Bind(ctx context.Context, dn string, password []byte) error
    BaseExists(ctx context.Context, baseDN string) error
    Search(ctx context.Context, q Query) (Page, error)              // size/time limits, NeverDerefAliases, attrs
    TLSState() (tls.ConnectionState, bool)
    Close() error
}
// ConnParams{URL, TLSMode, CAPEM, AllowTLS12, DialTimeout}; Query{BaseDN, Scope, Filter, Attributes, SizeLimit, TimeLimit}
// Page{Entries []RawEntry, Truncated bool, Referrals int}
// Errors: ErrTargetRefused, ErrUnreachable, ErrTimeout, ErrTLS, ErrInvalidCredentials,
//         ErrBaseNotFound, ErrDirectory (code only), ErrInvalidFilter, ErrInvalidBase, ErrInvalidURL.

// package ldapdir/ldapfake — in-memory Directory: entries by DN, base DN, aliases,
// referrals, size/time-limit behaviour, per-call error injection, records every
// Query (so tests assert the effective filter/base/deref/attributes sent).
```

```go
// package directory — domain service
type Store interface {                       // directorydb (pgx, RLS) + memstore implementation
    Atomic(ctx context.Context, scope store.Scope, fn func(tx any) error) error
}
type Tx interface {
    InsertConnection(ctx, store.DirectoryConnection) error
    Connection(ctx, tenantID, id string) (store.DirectoryConnection, error)
    ConnectionAnyTenant(ctx, id string) (store.DirectoryConnection, error)   // cross-tenant audit only
    ListConnections(ctx, tenantID string) ([]store.DirectoryConnection, error)
    CountConnections(ctx, tenantID string) (int, error)
    UpdateConnection(ctx, store.DirectoryConnection) error
    SetConnectionTest(ctx, tenantID, id, outcome string, at time.Time) error
    DeleteConnection(ctx, tenantID, id string) error
    UserByEmail(ctx, tenantID, email string) (store.User, error)
    UsersByEmails(ctx, tenantID string, emails []string) (map[string]store.User, error)   // preview status
    LinksByUIDs(ctx, tenantID, connID string, uids []string) (map[string]store.DirectoryLink, error)
    InsertUser(ctx, store.User) error
    UpdateImportedUser(ctx, tenantID, userID string, p store.ImportedProfile) error      // WHERE status='imported'
    UpsertLink(ctx, store.DirectoryLink) error
}
type Service struct { /* st, dir ldapdir.Directory, env *crypto.Envelope, policy, limits, cache (rate), audit, now */ }
func (s *Service) Create/Update/Get/List/Remove(...)
func (s *Service) Test(ctx, actor, tenantID string, in Input, connID string) (TestResult, error)
func (s *Service) Search(ctx, actor, tenantID, connID string, q SearchRequest) (SearchResult, error)
func (s *Service) Import(ctx, actor, tenantID, connID string, uids []string) (ImportResult, error)
```

```go
// package invite — additions
func (s *Service) Activate(ctx context.Context, actor tenantctx.Actor, tenantID string, userIDs []string, p Params) ([]ActivateItem, error)
// Tx gains: UserByID(ctx, tenantID, id) (store.User, error); PendingInvitationByEmail(...) (existing store fn)
// Service gains an escalation dependency: interface{ MayAssign(ctx, actor, tenantID string, roleIDs, groupIDs []string) error }
//   implemented by authz.Assigner (extracted from AssignRoles) — fake in tests.

// package user — additions
func (a *Admin) RemoveImported(ctx context.Context, actor tenantctx.Actor, uid string) error   // AdminStore gains DeleteImportedUser
// Deactivate/Reactivate: ErrInvalidState for status "imported"
```

Fakes used by tests: `ldapdir/ldapfake.Directory`, `memstore` (extended with
connections + links, same uniqueness semantics as SQL), `authz.NewFake()`
(existing), `cache.Memory` (existing, rate limit), audit capture writer
(existing test pattern), outbox capture (existing email test fake).

Integration: `tests/integration/ldap_import_test.go` (`//go:build integration`)
— TimescaleDB + Valkey + OpenFGA (existing harness) + the repo-owned OpenLDAP
container (research D17) with ldaps and StartTLS listeners and a test CA.

## D. Audit vocabulary (new `internal/audit` event types)
`directory_connection_created`, `directory_connection_updated`,
`directory_connection_deleted`, `directory_connection_tested`,
`directory_searched`, `directory_imported`, `imported_user_deleted`.
Activation reuses `invite_created` (`reason: "activation"`, `subject_kind:
"user"`, `details.invitation_id`). Details never include the bind password,
directory entries, names or e-mails — only ids, counts, the canonical filter
(≤ 1 KiB), base, scope, outcome/step.
