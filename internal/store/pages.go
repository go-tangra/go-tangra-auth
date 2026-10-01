package store

import (
	"context"
	"fmt"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// List-contract pages (go-tangra specs/032-server-side-tables): count the rows
// matching the filter inside the caller's tenant, clamp the request to the
// last page, then select the page under the very same WHERE clause, ORDER BY
// the Spec's constant expressions with the unique tie-breaker. Both queries
// run in the tenant-scoped transaction the caller opened, so row-level
// security bounds them as well.

// pageQuery names the parts of one page query. cols, countFrom, from and
// where are constants of this package; where is parameterised by args.
type pageQuery struct {
	cols      string
	countFrom string // FROM of the count (no joins that only add columns)
	from      string
	where     string
}

// args collects positional parameters and returns their $n placeholder.
type args []any

func (a *args) add(v any) string {
	*a = append(*a, v)
	return fmt.Sprintf("$%d", len(*a))
}

// runPage counts, clamps and selects one page.
func runPage[T any](ctx context.Context, tx pgx.Tx, q pageQuery, a args, spec listquery.Spec, req listquery.Request,
	scan func(pgx.Rows) (T, error)) ([]T, int, listquery.Request, error) {
	req = ListRequest(req, spec)
	countFrom := q.countFrom
	if countFrom == "" {
		countFrom = q.from
	}
	var total int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+countFrom+" WHERE "+q.where, a...).Scan(&total); err != nil {
		return nil, 0, req, err
	}
	req = req.Clamp(total)
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT %d OFFSET %d",
		q.cols, q.from, q.where, req.OrderBy(spec), req.Limit(), req.Offset()), a...)
	if err != nil {
		return nil, 0, req, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, serr := scan(rows)
		if serr != nil {
			return nil, 0, req, serr
		}
		out = append(out, v)
	}
	return out, total, req, rows.Err()
}

// userSearch is the users filter of the admin list (q over email and names).
func userSearch(tenantID string, f UserPageFilter, a *args) string {
	where := "u.tenant_id = " + a.add(tenantID)
	if f.Q != "" {
		p := a.add(escapeLike(f.Q)) // literal text: % and _ do not widen the match
		where += " AND (u.email ILIKE '%' || " + p + " || '%' OR u.display_name ILIKE '%' || " + p + " || '%' OR u.first_name ILIKE '%' || " + p +
			" || '%' OR u.last_name ILIKE '%' || " + p + " || '%')"
	}
	if f.Status != "" {
		where += " AND u.status = " + a.add(f.Status)
	}
	if f.ID != "" {
		where += " AND u.id = " + a.add(f.ID) + "::uuid"
	}
	return where
}

// PageUsers pages the users of a tenant matching f. Each user carries its
// directory origin (if imported) and, for invited users, the id of the most
// recent pending invitation (expired ones included: resend renews them).
func PageUsers(ctx context.Context, tx pgx.Tx, tenantID string, f UserPageFilter, req listquery.Request) ([]User, int, listquery.Request, error) {
	var a args
	where := userSearch(tenantID, f, &a)
	q := pageQuery{
		cols:      prefixCols("u.", userCols) + ", l.user_id IS NOT NULL, " + prefixCols("l.", linkCols) + ", inv.id",
		countFrom: "users u",
		from: `users u
		LEFT JOIN user_directory_links l ON l.user_id = u.id
		LEFT JOIN LATERAL (SELECT i.id FROM invitations i WHERE i.tenant_id = u.tenant_id AND i.email = u.email
			AND i.accepted_at IS NULL AND i.revoked_at IS NULL ORDER BY i.created_at DESC, i.id LIMIT 1) inv ON u.status = 'invited'`,
		where: where,
	}
	return runPage(ctx, tx, q, a, UserList, req, scanUserRow)
}

// scanUserRow reads one row of the users list (user, directory link, pending
// invitation).
func scanUserRow(rows pgx.Rows) (User, error) {
	var (
		u               User
		linked          bool
		l               DirectoryLink
		luid, ltid      *string
		lname, lui, ldn *string
		lfirst, llast   *time.Time
	)
	if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.PasswordHash, &u.PasswordChangedAt,
		&u.MFAEnabled, &u.MFASecretEnc, &u.MFALastCounter, &u.CreatedAt, &u.UpdatedAt, &u.LastSigninAt,
		&u.FirstName, &u.LastName, &u.Phone, &u.AvatarID, &u.DisplayNameExplicit, &u.ProfileUpdatedAt,
		&linked, &luid, &ltid, &l.ConnectionID, &lname, &lui, &ldn, &lfirst, &llast, &l.ImportedBy, &u.InvitationID); err != nil {
		return User{}, err
	}
	if linked {
		l.UserID, l.TenantID, l.ConnectionName, l.DirectoryUID, l.DirectoryDN = *luid, *ltid, *lname, *lui, *ldn
		l.FirstImportedAt, l.LastImportedAt = *lfirst, *llast
		u.Directory = &l
	}
	return u, nil
}

// auditCols is the audit row projection (scanAuditRow's order).
const auditCols = `a.id, a.ts, a.tenant_id, a.event_type, a.actor_user_id, a.actor_kind, coalesce(a.actor_service, ''), coalesce(a.subject_kind, ''), a.subject_id, a.outcome, a.reason,
		a.origin_ip_hash, a.user_agent, a.correlation_id, a.trace_id, a.details`

func scanAuditRow(rows pgx.Rows) (AuditRow, error) {
	var r AuditRow
	err := rows.Scan(&r.ID, &r.TS, &r.TenantID, &r.EventType, &r.ActorUserID, &r.ActorKind, &r.ActorService, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason,
		&r.OriginIPHash, &r.UserAgent, &r.CorrelationID, &r.TraceID, &r.Details)
	return r, err
}

// auditWhere is the audit filter of one tenant.
func auditWhere(tenantID string, f AuditPageFilter, a *args) string {
	where := "a.tenant_id = " + a.add(tenantID)
	if f.UserID != "" {
		p := a.add(f.UserID)
		where += " AND (a.actor_user_id::text = " + p + " OR a.subject_id::text = " + p + ")"
	}
	if f.EventType != "" {
		where += " AND a.event_type = " + a.add(f.EventType)
	}
	if !f.From.IsZero() {
		where += " AND a.ts >= " + a.add(f.From)
	}
	if !f.To.IsZero() {
		where += " AND a.ts <= " + a.add(f.To)
	}
	return where
}

// PageAudit pages the audit events of a tenant matching f.
func PageAudit(ctx context.Context, tx pgx.Tx, tenantID string, f AuditPageFilter, req listquery.Request) ([]AuditRow, int, listquery.Request, error) {
	var a args
	where := auditWhere(tenantID, f, &a)
	return runPage(ctx, tx, pageQuery{cols: auditCols, from: "auth_audit_events a", where: where}, a, AuditList, req, scanAuditRow)
}

// PageGroupMembers pages the members of one group of a tenant.
func PageGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID string, req listquery.Request) ([]GroupMember, int, listquery.Request, error) {
	var a args
	where := "m.tenant_id = " + a.add(tenantID) + " AND m.group_id = " + a.add(groupID)
	q := pageQuery{
		cols:      "m.user_id, u.email, u.display_name, u.status, u.avatar_id, m.added_at",
		countFrom: "group_members m",
		from:      "group_members m JOIN users u ON u.id = m.user_id",
		where:     where,
	}
	return runPage(ctx, tx, q, a, GroupMemberList, req, func(rows pgx.Rows) (GroupMember, error) {
		var m GroupMember
		err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Status, &m.AvatarID, &m.AddedAt)
		return m, err
	})
}
