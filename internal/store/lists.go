package store

import (
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// List definitions of the auth console tables (go-tangra
// specs/032-server-side-tables, contracts/sortable-fields.md "auth console").
// Sort fields map to constant SQL expressions only (the page queries alias
// users as u, group_members as m and auth_audit_events as a); in-memory lists
// sort the same public names in Go (see the Key functions of each view). No
// sort field exposes a secret, a hash or an attribute the list does not show.
// gRPC lists (profiles, contacts, member walks) and the backup walks keep
// their own queries.
var (
	// UserList pages GET /admin/users by email.
	UserList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"email":          {Expr: "u.email", Text: true},
			"display_name":   {Expr: "u.display_name", Text: true},
			"status":         {Expr: "u.status"},
			"last_signin_at": {Expr: "u.last_signin_at", DefaultDir: listquery.Desc},
			"created_at":     {Expr: "u.created_at", DefaultDir: listquery.Desc},
		},
		Default: "email", TieBreak: "u.id",
	}
	// AuditList pages GET /admin/audit, newest first, within a time window
	// (AuditWindow by default; research D6). The id breaks timestamp ties.
	AuditList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"ts": {Expr: "a.ts", DefaultDir: listquery.Desc},
		},
		Default: "ts", TieBreak: "a.id", DefaultSize: 50,
	}
	// GroupMemberList pages GET /admin/groups/{id}/members, latest first.
	GroupMemberList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"added_at":     {Expr: "m.added_at", DefaultDir: listquery.Desc},
			"email":        {Expr: "u.email", Text: true},
			"display_name": {Expr: "u.display_name", Text: true},
			"status":       {Expr: "u.status"},
		},
		Default: "added_at", TieBreak: "m.user_id",
	}

	// The lists below are small per-tenant configuration sets that the
	// services already load whole (with their permission checks); the
	// handlers sort and window them with listquery.SortSlice / Window. Their
	// Expr is the public field name the view's key function answers; it is
	// never used in SQL.

	// GroupList pages GET /admin/groups by name.
	GroupList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":         {Expr: "name", Text: true},
			"member_count": {Expr: "member_count", DefaultDir: listquery.Desc},
			"created_at":   {Expr: "created_at", DefaultDir: listquery.Desc},
		},
		Default: "name", TieBreak: "id",
	}
	// RoleList pages GET /admin/roles by display name.
	RoleList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"display_name": {Expr: "display_name", Text: true},
			"slug":         {Expr: "slug", Text: true},
			"origin":       {Expr: "origin"},
		},
		Default: "display_name", TieBreak: "id",
	}
	// ClientList pages GET /admin/clients by display name.
	ClientList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"display_name": {Expr: "display_name", Text: true},
			"client_id":    {Expr: "client_id"},
		},
		Default: "display_name", TieBreak: "client_id",
	}
	// TenantList pages GET /operator/tenants by display name.
	TenantList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"display_name": {Expr: "display_name", Text: true},
			"slug":         {Expr: "slug"},
			"status":       {Expr: "status"},
			"kind":         {Expr: "kind"},
			"created_at":   {Expr: "created_at", DefaultDir: listquery.Desc},
		},
		Default: "display_name", TieBreak: "id",
	}
	// SessionList pages GET /sessions (the caller's own), newest first.
	SessionList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"created_at":   {Expr: "created_at", DefaultDir: listquery.Desc},
			"last_seen_at": {Expr: "last_seen_at", DefaultDir: listquery.Desc},
			"expires_at":   {Expr: "expires_at"},
		},
		Default: "created_at", TieBreak: "id",
	}
	// DirectoryList pages GET /admin/directories by name.
	DirectoryList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":       {Expr: "name", Text: true},
			"created_at": {Expr: "created_at", DefaultDir: listquery.Desc},
		},
		Default: "name", TieBreak: "id",
	}
)

// AuditWindow bounds an audit page without from/to so the exact count stays
// cheap on the hypertable (research D6).
const AuditWindow = 7 * 24 * time.Hour

// ListRequest completes r with the Spec's defaults (a zero Request from an
// internal caller pages with the defaults); an invalid hand-built Request
// falls back to the defaults entirely.
func ListRequest(r listquery.Request, s listquery.Spec) listquery.Request {
	out, err := listquery.New(r.Page, r.PageSize, r.Sort, r.Order, s)
	if err != nil {
		out, _ = listquery.New(0, 0, "", "", s)
	}
	return out
}

// UserPageFilter selects a users page (q matches email, display, first or
// last name; status and id are exact; id is a known user id, never raw input).
type UserPageFilter struct {
	Q, Status, ID string
}

// AuditPageFilter selects an audit page. From and To bound ts inclusively; a
// zero From is unbounded (legacy count). UserID matches actor or subject.
type AuditPageFilter struct {
	UserID, EventType string
	From, To          time.Time
}
