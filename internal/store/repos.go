package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The repositories below are thin, tenant-scoped SQL wrappers. Callers run them
// inside Store.Tx so that the RLS settings are in force.

// ---------------------------------------------------------------- tenants

const tenantCols = "id, slug, display_name, status, kind, policy, created_at, updated_at"

func scanTenant(r pgx.Row) (Tenant, error) {
	var t Tenant
	err := r.Scan(&t.ID, &t.Slug, &t.DisplayName, &t.Status, &t.Kind, &t.Policy, &t.CreatedAt, &t.UpdatedAt)
	return t, notFound(err)
}

// InsertTenant creates a tenant.
func InsertTenant(ctx context.Context, tx pgx.Tx, t Tenant) error {
	_, err := tx.Exec(ctx, `INSERT INTO tenants (id, slug, display_name, status, kind, policy) VALUES ($1,$2,$3,$4,$5,$6)`,
		t.ID, t.Slug, t.DisplayName, t.Status, t.Kind, t.Policy)
	return err
}

// GetTenant by id.
func GetTenant(ctx context.Context, tx pgx.Tx, id string) (Tenant, error) {
	return scanTenant(tx.QueryRow(ctx, "SELECT "+tenantCols+" FROM tenants WHERE id = $1", id))
}

// GetTenantBySlug by slug.
func GetTenantBySlug(ctx context.Context, tx pgx.Tx, slug string) (Tenant, error) {
	return scanTenant(tx.QueryRow(ctx, "SELECT "+tenantCols+" FROM tenants WHERE slug = $1", slug))
}

// ListTenants (operator scope).
func ListTenants(ctx context.Context, tx pgx.Tx) ([]Tenant, error) {
	rows, err := tx.Query(ctx, "SELECT "+tenantCols+" FROM tenants ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateTenantStatus sets active/suspended.
func UpdateTenantStatus(ctx context.Context, tx pgx.Tx, id, status string) error {
	ct, err := tx.Exec(ctx, "UPDATE tenants SET status = $2, updated_at = now() WHERE id = $1", id, status)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// UpdateTenantPolicy replaces the policy document.
func UpdateTenantPolicy(ctx context.Context, tx pgx.Tx, id string, policy []byte) error {
	ct, err := tx.Exec(ctx, "UPDATE tenants SET policy = $2, updated_at = now() WHERE id = $1", id, policy)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- users

const userCols = "id, tenant_id, email, display_name, status, password_hash, password_changed_at, mfa_enabled, mfa_secret_enc, mfa_last_counter, created_at, updated_at, last_signin_at, first_name, last_name, phone, avatar_id, display_name_explicit, profile_updated_at"

func scanUser(r pgx.Row) (User, error) {
	var u User
	err := r.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.PasswordHash, &u.PasswordChangedAt,
		&u.MFAEnabled, &u.MFASecretEnc, &u.MFALastCounter, &u.CreatedAt, &u.UpdatedAt, &u.LastSigninAt,
		&u.FirstName, &u.LastName, &u.Phone, &u.AvatarID, &u.DisplayNameExplicit, &u.ProfileUpdatedAt)
	return u, notFound(err)
}

// InsertUser creates a user.
func InsertUser(ctx context.Context, tx pgx.Tx, u User) error {
	_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, display_name, status, password_hash, first_name, last_name, display_name_explicit)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		u.ID, u.TenantID, u.Email, u.DisplayName, u.Status, u.PasswordHash, u.FirstName, u.LastName, DisplayNameExplicit(u))
	return err
}

// GetUser by tenant + id.
func GetUser(ctx context.Context, tx pgx.Tx, tenantID, id string) (User, error) {
	return scanUser(tx.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// GetUserByEmail by tenant + email.
func GetUserByEmail(ctx context.Context, tx pgx.Tx, tenantID, email string) (User, error) {
	return scanUser(tx.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE tenant_id = $1 AND email = $2", tenantID, email))
}

// ListUsers with optional search and status. Each user carries its directory
// origin (if imported from one) and, for invited users, the id of the most
// recent pending invitation (expired ones included: resend renews them).
func ListUsers(ctx context.Context, tx pgx.Tx, tenantID, q, status string, limit int) ([]User, error) {
	rows, err := tx.Query(ctx, "SELECT "+prefixCols("u.", userCols)+", l.user_id IS NOT NULL, "+prefixCols("l.", linkCols)+`, inv.id
		FROM users u
		LEFT JOIN user_directory_links l ON l.user_id = u.id
		LEFT JOIN LATERAL (SELECT i.id FROM invitations i WHERE i.tenant_id = u.tenant_id AND i.email = u.email
			AND i.accepted_at IS NULL AND i.revoked_at IS NULL ORDER BY i.created_at DESC, i.id LIMIT 1) inv ON u.status = 'invited'
		WHERE u.tenant_id = $1
		AND ($2 = '' OR u.email ILIKE '%' || $2 || '%' OR u.display_name ILIKE '%' || $2 || '%' OR u.first_name ILIKE '%' || $2 || '%' OR u.last_name ILIKE '%' || $2 || '%')
		AND ($3 = '' OR u.status = $3) ORDER BY u.created_at, u.id LIMIT $4`, tenantID, q, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
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
			return nil, err
		}
		if linked {
			l.UserID, l.TenantID, l.ConnectionName, l.DirectoryUID, l.DirectoryDN = *luid, *ltid, *lname, *lui, *ldn
			l.FirstImportedAt, l.LastImportedAt = *lfirst, *llast
			u.Directory = &l
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// prefixCols qualifies a comma-separated column list with a table alias.
func prefixCols(alias, cols string) string {
	parts := strings.Split(cols, ", ")
	for i, c := range parts {
		parts[i] = alias + c
	}
	return strings.Join(parts, ", ")
}

// UpdateUserStatus changes status.
func UpdateUserStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string) error {
	ct, err := tx.Exec(ctx, "UPDATE users SET status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id, status)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetPassword stores a new hash; activates invited users.
func SetPassword(ctx context.Context, tx pgx.Tx, tenantID, id, hash string) error {
	ct, err := tx.Exec(ctx, `UPDATE users SET password_hash = $3, password_changed_at = now(), updated_at = now(),
		status = CASE WHEN status = 'invited' THEN 'active' ELSE status END WHERE tenant_id = $1 AND id = $2`, tenantID, id, hash)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetMFA stores the encrypted seed and enabled flag.
func SetMFA(ctx context.Context, tx pgx.Tx, tenantID, id string, enabled bool, secretEnc []byte) error {
	ct, err := tx.Exec(ctx, "UPDATE users SET mfa_enabled = $3, mfa_secret_enc = $4, mfa_last_counter = 0, updated_at = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, enabled, secretEnc)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ResetCredentials is the break-glass reset: it clears the password, the MFA
// seed and its replay counter, removes the user's security keys and returns
// the user to "invited" so the only way back in is a fresh invitation. Only
// active or invited users qualify; imported and deactivated users are refused
// with ErrNotFound.
func ResetCredentials(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, `UPDATE users SET password_hash = NULL, password_changed_at = NULL, mfa_enabled = false,
		mfa_secret_enc = NULL, mfa_last_counter = 0, status = 'invited', updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND status IN ('active','invited')`, tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(ctx, "DELETE FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2", tenantID, id)
	return err
}

// SetMFACounter records the last accepted TOTP counter (replay protection).
func SetMFACounter(ctx context.Context, tx pgx.Tx, tenantID, id string, counter int64) error {
	_, err := tx.Exec(ctx, "UPDATE users SET mfa_last_counter = $3 WHERE tenant_id = $1 AND id = $2 AND mfa_last_counter < $3", tenantID, id, counter)
	return err
}

// TouchSignin records a successful sign-in.
func TouchSignin(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, "UPDATE users SET last_signin_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id)
	return err
}

// ---------------------------------------------------------------- recovery codes

// ReplaceRecoveryCodes stores hashes (previous ones are dropped).
func ReplaceRecoveryCodes(ctx context.Context, tx pgx.Tx, tenantID, userID string, hashes []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2", tenantID, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (user_id, tenant_id, code_hash) VALUES ($1,$2,$3)", userID, tenantID, h); err != nil {
			return err
		}
	}
	return nil
}

// ListRecoveryCodeHashes returns unused hashes.
func ListRecoveryCodeHashes(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]string, error) {
	rows, err := tx.Query(ctx, "SELECT code_hash FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL", tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UseRecoveryCode marks a hash used; ErrNotFound if already used.
func UseRecoveryCode(ctx context.Context, tx pgx.Tx, tenantID, userID, hash string) error {
	ct, err := tx.Exec(ctx, "UPDATE recovery_codes SET used_at = now() WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL", tenantID, userID, hash)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- roles

const roleCols = "id, tenant_id, slug, display_name, builtin, created_at, updated_at"

func scanRole(r pgx.Row) (Role, error) {
	var x Role
	err := r.Scan(&x.ID, &x.TenantID, &x.Slug, &x.DisplayName, &x.Builtin, &x.CreatedAt, &x.UpdatedAt)
	return x, notFound(err)
}

// InsertRole creates a role.
func InsertRole(ctx context.Context, tx pgx.Tx, r Role) error {
	_, err := tx.Exec(ctx, "INSERT INTO roles (id, tenant_id, slug, display_name, builtin) VALUES ($1,$2,$3,$4,$5)", r.ID, r.TenantID, r.Slug, r.DisplayName, r.Builtin)
	return err
}

// GetRole by tenant + id.
func GetRole(ctx context.Context, tx pgx.Tx, tenantID, id string) (Role, error) {
	return scanRole(tx.QueryRow(ctx, "SELECT "+roleCols+" FROM roles WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListRoles for a tenant.
func ListRoles(ctx context.Context, tx pgx.Tx, tenantID string) ([]Role, error) {
	rows, err := tx.Query(ctx, "SELECT "+roleCols+" FROM roles WHERE tenant_id = $1 ORDER BY builtin DESC, slug", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRoleName renames a custom role.
func UpdateRoleName(ctx context.Context, tx pgx.Tx, tenantID, id, name string) error {
	_, err := tx.Exec(ctx, "UPDATE roles SET display_name = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND NOT builtin", tenantID, id, name)
	return err
}

// RemoveRole removes a custom role (bindings/permissions cascade).
func RemoveRole(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM roles WHERE tenant_id = $1 AND id = $2 AND NOT builtin", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ReplaceRolePermissions mirrors the FGA grants.
func ReplaceRolePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, perms [][2]string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM role_permissions WHERE tenant_id = $1 AND role_id = $2", tenantID, roleID); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(ctx, "INSERT INTO role_permissions (role_id, tenant_id, resource, action) VALUES ($1,$2,$3,$4)", roleID, tenantID, p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

// ListRolePermissions returns resource/action pairs.
func ListRolePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string) ([][2]string, error) {
	rows, err := tx.Query(ctx, "SELECT resource, action FROM role_permissions WHERE tenant_id = $1 AND role_id = $2 ORDER BY resource, action", tenantID, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ReplaceRoleBindings mirrors the FGA assignments for one user.
func ReplaceRoleBindings(ctx context.Context, tx pgx.Tx, tenantID, userID, grantedBy string, roleIDs []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM role_bindings WHERE tenant_id = $1 AND user_id = $2", tenantID, userID); err != nil {
		return err
	}
	for _, r := range roleIDs {
		if _, err := tx.Exec(ctx, "INSERT INTO role_bindings (user_id, role_id, tenant_id, granted_by) VALUES ($1,$2,$3,NULLIF($4,'')::uuid)", userID, r, tenantID, grantedBy); err != nil {
			return err
		}
	}
	return nil
}

// UserRoleSlugs returns the role slugs bound to a user.
func UserRoleSlugs(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT r.slug FROM role_bindings b JOIN roles r ON r.id = b.role_id
		WHERE b.tenant_id = $1 AND b.user_id = $2 ORDER BY r.slug`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// CountUsersWithRole counts active holders of a role slug (last-owner rule).
func CountUsersWithRole(ctx context.Context, tx pgx.Tx, tenantID, slug string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM role_bindings b JOIN roles r ON r.id = b.role_id JOIN users u ON u.id = b.user_id
		WHERE b.tenant_id = $1 AND r.slug = $2 AND u.status = 'active'`, tenantID, slug).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- permissions registry

// UpsertPermission registers a permission for a tenant.
func UpsertPermission(ctx context.Context, tx pgx.Tx, tenantID, resource, action, description, registeredBy string) error {
	_, err := tx.Exec(ctx, `INSERT INTO permissions (tenant_id, resource, action, description, registered_by) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id, resource, action) DO UPDATE SET description = EXCLUDED.description, registered_by = EXCLUDED.registered_by`,
		tenantID, resource, action, description, registeredBy)
	return err
}

// ListPermissions for a tenant: resource, action, description.
func ListPermissions(ctx context.Context, tx pgx.Tx, tenantID string) ([][3]string, error) {
	rows, err := tx.Query(ctx, "SELECT resource, action, description FROM permissions WHERE tenant_id = $1 ORDER BY resource, action", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var p [3]string
		if err := rows.Scan(&p[0], &p[1], &p[2]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- sessions

const sessionCols = "id, tenant_id, user_id, secret_hash, amr, created_at, last_seen_at, expires_at, ip_hash, user_agent, revoked_at, revoked_reason"

func scanSession(r pgx.Row) (Session, error) {
	var s Session
	err := r.Scan(&s.ID, &s.TenantID, &s.UserID, &s.SecretHash, &s.AMR, &s.CreatedAt, &s.LastSeen, &s.ExpiresAt, &s.IPHash, &s.UserAgent, &s.RevokedAt, &s.RevokedReason)
	return s, notFound(err)
}

// InsertSession creates a session row.
func InsertSession(ctx context.Context, tx pgx.Tx, s Session) error {
	_, err := tx.Exec(ctx, `INSERT INTO sessions (id, tenant_id, user_id, secret_hash, amr, expires_at, ip_hash, user_agent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		s.ID, s.TenantID, s.UserID, s.SecretHash, s.AMR, s.ExpiresAt, s.IPHash, s.UserAgent)
	return err
}

// GetSession by tenant + id.
func GetSession(ctx context.Context, tx pgx.Tx, tenantID, id string) (Session, error) {
	return scanSession(tx.QueryRow(ctx, "SELECT "+sessionCols+" FROM sessions WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListUserSessions returns live sessions of a user.
func ListUserSessions(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]Session, error) {
	rows, err := tx.Query(ctx, "SELECT "+sessionCols+" FROM sessions WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC", tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// TouchSession updates last_seen_at.
func TouchSession(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, "UPDATE sessions SET last_seen_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id)
	return err
}

// RevokeSession marks one session.
func RevokeSession(ctx context.Context, tx pgx.Tx, tenantID, id, reason string) error {
	_, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = now(), revoked_reason = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL", tenantID, id, reason)
	return err
}

// RevokeUserSessions marks all sessions of a user, optionally keeping one.
func RevokeUserSessions(ctx context.Context, tx pgx.Tx, tenantID, userID, reason, keepID string) error {
	_, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = now(), revoked_reason = $3 WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND id::text <> $4", tenantID, userID, reason, keepID)
	return err
}

// RevokeTenantSessions marks all sessions of a tenant.
func RevokeTenantSessions(ctx context.Context, tx pgx.Tx, tenantID, reason string) error {
	_, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE tenant_id = $1 AND revoked_at IS NULL", tenantID, reason)
	return err
}

// ---------------------------------------------------------------- revocations feed

// InsertRevocation appends to the feed.
func InsertRevocation(ctx context.Context, tx pgx.Tx, r Revocation) error {
	_, err := tx.Exec(ctx, "INSERT INTO revocations (ts, kind, subject_id, tenant_id, reason) VALUES ($1,$2,$3,$4,$5)", r.TS, r.Kind, r.SubjectID, r.TenantID, r.Reason)
	return err
}

// ListRevocationsSince returns entries after ts (system scope).
func ListRevocationsSince(ctx context.Context, tx pgx.Tx, since time.Time, limit int) ([]Revocation, error) {
	rows, err := tx.Query(ctx, "SELECT ts, kind, subject_id, tenant_id, reason FROM revocations WHERE ts > $1 ORDER BY ts LIMIT $2", since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.TS, &r.Kind, &r.SubjectID, &r.TenantID, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- signing keys (system scope)

const keyCols = "kid, public_key, private_key_enc, state, created_at, retiring_at, retired_at"

// InsertSigningKey stores a new key.
func InsertSigningKey(ctx context.Context, tx pgx.Tx, k SigningKey) error {
	_, err := tx.Exec(ctx, "INSERT INTO signing_keys (kid, public_key, private_key_enc, state) VALUES ($1,$2,$3,$4)", k.KID, k.PublicKey, k.PrivateEnc, k.State)
	return err
}

// ListSigningKeys returns all keys.
func ListSigningKeys(ctx context.Context, tx pgx.Tx) ([]SigningKey, error) {
	rows, err := tx.Query(ctx, "SELECT "+keyCols+" FROM signing_keys ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.KID, &k.PublicKey, &k.PrivateEnc, &k.State, &k.CreatedAt, &k.RetiringAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetSigningKeyState transitions a key.
func SetSigningKeyState(ctx context.Context, tx pgx.Tx, kid, state string) error {
	_, err := tx.Exec(ctx, `UPDATE signing_keys SET state = $2,
		retiring_at = CASE WHEN $2 = 'retiring' THEN now() ELSE retiring_at END,
		retired_at  = CASE WHEN $2 = 'retired'  THEN now() ELSE retired_at END WHERE kid = $1`, kid, state)
	return err
}

// RemoveSigningKey drops a fully expired key.
func RemoveSigningKey(ctx context.Context, tx pgx.Tx, kid string) error {
	_, err := tx.Exec(ctx, "DELETE FROM signing_keys WHERE kid = $1 AND state = 'retired'", kid)
	return err
}

// ---------------------------------------------------------------- invitations

const invCols = "id, tenant_id, email, role_ids, token_hash, invited_by, expires_at, accepted_at, revoked_at, group_ids, first_name, last_name"

func scanInvitation(r pgx.Row) (Invitation, error) {
	var i Invitation
	err := r.Scan(&i.ID, &i.TenantID, &i.Email, &i.RoleIDs, &i.TokenHash, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.RevokedAt, &i.GroupIDs, &i.FirstName, &i.LastName)
	return i, notFound(err)
}

// InsertInvitation creates an invitation.
func InsertInvitation(ctx context.Context, tx pgx.Tx, i Invitation) error {
	_, err := tx.Exec(ctx, "INSERT INTO invitations (id, tenant_id, email, role_ids, token_hash, invited_by, expires_at, group_ids, first_name, last_name) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::uuid,$7,$8,$9,$10)",
		i.ID, i.TenantID, i.Email, nonNilIDs(i.RoleIDs), i.TokenHash, deref(i.InvitedBy), i.ExpiresAt, nonNilIDs(i.GroupIDs), i.FirstName, i.LastName)
	return err
}

// GetInvitationByTokenHash (system scope: the acceptor is not signed in yet).
func GetInvitationByTokenHash(ctx context.Context, tx pgx.Tx, hash string) (Invitation, error) {
	return scanInvitation(tx.QueryRow(ctx, "SELECT "+invCols+" FROM invitations WHERE token_hash = $1", hash))
}

// GetInvitation by tenant + id.
func GetInvitation(ctx context.Context, tx pgx.Tx, tenantID, id string) (Invitation, error) {
	return scanInvitation(tx.QueryRow(ctx, "SELECT "+invCols+" FROM invitations WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// PendingInvitationByEmail returns the most recent still-usable invitation
// (not accepted, not revoked, not expired) for an email. Used by Bootstrap to
// stay idempotent: a re-run reuses the pending invite instead of creating a
// duplicate. Returns ErrNotFound when none is outstanding.
func PendingInvitationByEmail(ctx context.Context, tx pgx.Tx, tenantID, email string) (Invitation, error) {
	return scanInvitation(tx.QueryRow(ctx, "SELECT "+invCols+" FROM invitations WHERE tenant_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1", tenantID, email))
}

// RevokePendingInvitations revokes every outstanding invitation for an email
// so only the newest link works.
func RevokePendingInvitations(ctx context.Context, tx pgx.Tx, tenantID, email string) (int64, error) {
	ct, err := tx.Exec(ctx, "UPDATE invitations SET revoked_at = now() WHERE tenant_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL", tenantID, email)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// MarkInvitationAccepted sets accepted_at once.
func MarkInvitationAccepted(ctx context.Context, tx pgx.Tx, id string) error {
	ct, err := tx.Exec(ctx, "UPDATE invitations SET accepted_at = now() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()", id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RotateInvitationToken sets a new token hash/expiry (resend).
func RotateInvitationToken(ctx context.Context, tx pgx.Tx, tenantID, id, hash string, expires time.Time) error {
	ct, err := tx.Exec(ctx, "UPDATE invitations SET token_hash = $3, expires_at = $4 WHERE tenant_id = $1 AND id = $2 AND accepted_at IS NULL", tenantID, id, hash, expires)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- recovery requests

// InsertRecoveryRequest creates a request.
func InsertRecoveryRequest(ctx context.Context, tx pgx.Tx, r RecoveryRequest, ipHash string) error {
	_, err := tx.Exec(ctx, "INSERT INTO recovery_requests (id, tenant_id, user_id, token_hash, expires_at, requested_ip_hash) VALUES ($1,$2,$3,$4,$5,$6)",
		r.ID, r.TenantID, r.UserID, r.TokenHash, r.ExpiresAt, ipHash)
	return err
}

// UseRecoveryRequest consumes a token hash once; returns the request.
func UseRecoveryRequest(ctx context.Context, tx pgx.Tx, hash string) (RecoveryRequest, error) {
	var r RecoveryRequest
	err := tx.QueryRow(ctx, `UPDATE recovery_requests SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING id, tenant_id, user_id, token_hash, expires_at, used_at`, hash).Scan(&r.ID, &r.TenantID, &r.UserID, &r.TokenHash, &r.ExpiresAt, &r.UsedAt)
	return r, notFound(err)
}

// ---------------------------------------------------------------- client applications

// InsertClient registers a client application.
func InsertClient(ctx context.Context, tx pgx.Tx, c ClientApplication) error {
	_, err := tx.Exec(ctx, "INSERT INTO client_applications (client_id, tenant_id, display_name, redirect_uris, public, secret_hash) VALUES ($1,$2,$3,$4,$5,$6)",
		c.ClientID, c.TenantID, c.DisplayName, c.RedirectURIs, c.Public, c.SecretHash)
	return err
}

// GetClient by id (system scope for the authorize endpoint).
func GetClient(ctx context.Context, tx pgx.Tx, clientID string) (ClientApplication, error) {
	var c ClientApplication
	err := tx.QueryRow(ctx, "SELECT client_id, tenant_id, display_name, redirect_uris, public, secret_hash FROM client_applications WHERE client_id = $1", clientID).
		Scan(&c.ClientID, &c.TenantID, &c.DisplayName, &c.RedirectURIs, &c.Public, &c.SecretHash)
	return c, notFound(err)
}

// ListClients for a tenant.
func ListClients(ctx context.Context, tx pgx.Tx, tenantID string) ([]ClientApplication, error) {
	rows, err := tx.Query(ctx, "SELECT client_id, tenant_id, display_name, redirect_uris, public, secret_hash FROM client_applications WHERE tenant_id = $1 ORDER BY client_id", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientApplication
	for rows.Next() {
		var c ClientApplication
		if err := rows.Scan(&c.ClientID, &c.TenantID, &c.DisplayName, &c.RedirectURIs, &c.Public, &c.SecretHash); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- operator grants

// InsertOperatorGrant creates a grant.
func InsertOperatorGrant(ctx context.Context, tx pgx.Tx, g OperatorGrant) error {
	_, err := tx.Exec(ctx, "INSERT INTO operator_grants (id, operator_user_id, tenant_id, reason, expires_at) VALUES ($1,$2,$3,$4,$5)", g.ID, g.OperatorUserID, g.TenantID, g.Reason, g.ExpiresAt)
	return err
}

// ActiveOperatorGrant returns a live grant for operator+tenant.
func ActiveOperatorGrant(ctx context.Context, tx pgx.Tx, operatorID, tenantID string) (OperatorGrant, error) {
	var g OperatorGrant
	err := tx.QueryRow(ctx, `SELECT id, operator_user_id, tenant_id, reason, granted_at, expires_at, revoked_at FROM operator_grants
		WHERE operator_user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > now() ORDER BY granted_at DESC LIMIT 1`, operatorID, tenantID).
		Scan(&g.ID, &g.OperatorUserID, &g.TenantID, &g.Reason, &g.GrantedAt, &g.ExpiresAt, &g.RevokedAt)
	return g, notFound(err)
}

// ---------------------------------------------------------------- audit

// InsertAuditRows batch-inserts audit events (system scope: rows carry their tenant).
// InsertAuditRows writes a batch with plain INSERTs: COPY is refused on
// row-level-security tables for roles without BYPASSRLS.
func InsertAuditRows(ctx context.Context, tx pgx.Tx, rows []AuditRow) error {
	if len(rows) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, r := range rows {
		b.Queue(`INSERT INTO auth_audit_events (ts, tenant_id, event_type, actor_user_id, actor_kind, actor_service, subject_kind, subject_id, outcome, reason,
			origin_ip_hash, user_agent, correlation_id, trace_id, details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			r.TS, r.TenantID, r.EventType, r.ActorUserID, r.ActorKind, r.ActorService, r.SubjectKind, r.SubjectID,
			r.Outcome, r.Reason, r.OriginIPHash, r.UserAgent, r.CorrelationID, r.TraceID, r.Details)
	}
	res := tx.SendBatch(ctx, b)
	defer func() { _ = res.Close() }()
	for range rows {
		if _, err := res.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// QueryAudit lists events of a tenant with filters; cursor = ts of the last row seen.
func QueryAudit(ctx context.Context, tx pgx.Tx, tenantID, userID, eventType string, from, to, cursor time.Time, limit int) ([]AuditRow, error) {
	rows, err := tx.Query(ctx, `SELECT ts, tenant_id, event_type, actor_user_id, actor_kind, actor_service, subject_kind, subject_id, outcome, reason,
		origin_ip_hash, user_agent, correlation_id, trace_id, details FROM auth_audit_events
		WHERE tenant_id = $1 AND ($2 = '' OR actor_user_id::text = $2 OR subject_id::text = $2) AND ($3 = '' OR event_type = $3)
		AND ts >= $4 AND ts <= $5 AND ($6::timestamptz IS NULL OR ts < $6) ORDER BY ts DESC LIMIT $7`,
		tenantID, userID, eventType, from, to, nullTime(cursor), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.TS, &r.TenantID, &r.EventType, &r.ActorUserID, &r.ActorKind, &r.ActorService, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason,
			&r.OriginIPHash, &r.UserAgent, &r.CorrelationID, &r.TraceID, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertSigninAttempt records an attempt.
func InsertSigninAttempt(ctx context.Context, tx pgx.Tx, tenantID, userID, emailHash, ipHash, outcome, reason string) error {
	_, err := tx.Exec(ctx, "INSERT INTO signin_attempts (ts, tenant_id, user_id, email_hash, ip_hash, outcome, reason) VALUES (now(), NULLIF($1,'')::uuid, NULLIF($2,'')::uuid, $3, $4, $5, $6)",
		tenantID, userID, emailHash, ipHash, outcome, reason)
	return err
}

// ---------------------------------------------------------------- outbox

// EnqueueOutbox stores an email to send.
func EnqueueOutbox(ctx context.Context, tx pgx.Tx, it OutboxItem) error {
	_, err := tx.Exec(ctx, "INSERT INTO outbox (id, tenant_id, kind, to_email, payload_enc) VALUES ($1,$2,$3,$4,$5)", it.ID, it.TenantID, it.Kind, it.ToEmail, it.PayloadEnc)
	return err
}

// ClaimOutbox returns due, unretired items, counts the attempt and pushes the
// next one out by 30 s · 2^attempts, capped at one hour (system scope). The
// exponent is bounded so a long-lived row cannot overflow the interval.
func ClaimOutbox(ctx context.Context, tx pgx.Tx, limit int) ([]OutboxItem, error) {
	rows, err := tx.Query(ctx, `UPDATE outbox SET attempts = attempts + 1,
		next_attempt_at = now() + least(interval '30 seconds' * power(2, least(attempts, 7)), interval '1 hour')
		WHERE id IN (SELECT id FROM outbox WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
			ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING id, tenant_id, kind, to_email, payload_enc, attempts, next_attempt_at`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		if err := rows.Scan(&it.ID, &it.TenantID, &it.Kind, &it.ToEmail, &it.PayloadEnc, &it.Attempts, &it.NextAttemptAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkOutboxSent completes an item.
func MarkOutboxSent(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, "UPDATE outbox SET sent_at = now() WHERE id = $1", id)
	return err
}

// MarkOutboxFailed retires an item: it is never claimed again. reason is
// clipped to the column's 200 characters.
func MarkOutboxFailed(ctx context.Context, tx pgx.Tx, id, reason string) error {
	if r := []rune(reason); len(r) > 200 {
		reason = string(r[:200])
	}
	_, err := tx.Exec(ctx, "UPDATE outbox SET failed_at = now(), last_error = $2 WHERE id = $1 AND sent_at IS NULL", id, reason)
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// GetSessionBySecretHash resolves a cookie secret to its session. Callers run
// it under the system scope: the tenant is not known before the lookup.
func GetSessionBySecretHash(ctx context.Context, tx pgx.Tx, hash []byte) (Session, error) {
	var s Session
	err := tx.QueryRow(ctx, `SELECT id, tenant_id, user_id, secret_hash, amr, created_at, last_seen_at, expires_at, ip_hash, user_agent, revoked_at, revoked_reason
		FROM sessions WHERE secret_hash = $1`, hash).Scan(&s.ID, &s.TenantID, &s.UserID, &s.SecretHash, &s.AMR, &s.CreatedAt, &s.LastSeen, &s.ExpiresAt, &s.IPHash, &s.UserAgent, &s.RevokedAt, &s.RevokedReason)
	return s, notFound(err)
}

func nonNilIDs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// DisplayNameExplicit reports whether a user's display name was chosen by
// hand: set, not the email, not the email's local part, and not derived from
// first/last names.
func DisplayNameExplicit(u User) bool {
	if u.DisplayNameExplicit {
		return true
	}
	if u.DisplayName == "" || u.DisplayName == u.Email {
		return false
	}
	if local, _, ok := strings.Cut(u.Email, "@"); ok && u.DisplayName == local {
		return false
	}
	return u.FirstName == "" && u.LastName == ""
}
