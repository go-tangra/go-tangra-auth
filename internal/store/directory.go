package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------- directory connections (feature 016)

// DirectoryConnection row. BindPasswordEnc is crypto.Envelope ciphertext
// (associated data "ldap-bind:<tenant_id>:<id>"); it is never copied into an
// API view.
type DirectoryConnection struct {
	ID, TenantID, Name, Kind, URL, TLSMode string
	AllowTLS12                             bool
	CAPEM                                  string // "" = system roots
	BindDN                                 string
	BindPasswordEnc                        []byte
	BaseDN, BaseFilter                     string
	AttrUID, AttrEmail, AttrDisplayName    string
	AttrFirstName, AttrLastName            string
	SizeLimit, TimeLimitSeconds            int
	LastTestAt                             *time.Time
	LastTestOutcome                        *string
	CreatedBy, UpdatedBy                   *string
	CreatedAt, UpdatedAt                   time.Time
}

// DirectoryLink is a user's directory origin (one per user).
type DirectoryLink struct {
	UserID, TenantID                string
	ConnectionID                    *string // nil once the connection was deleted
	ConnectionName                  string  // snapshot for display after deletion
	DirectoryUID, DirectoryDN       string
	FirstImportedAt, LastImportedAt time.Time
	ImportedBy                      *string
}

// ImportedProfile is what a re-import may refresh on a still-imported user.
type ImportedProfile struct {
	Email, DisplayName, FirstName, LastName string
	DisplayNameExplicit                     bool
}

const dirConnCols = "id, tenant_id, name, kind, url, tls_mode, allow_tls12, COALESCE(ca_pem, ''), bind_dn, bind_password_enc, base_dn, base_filter, attr_uid, attr_email, attr_display_name, attr_first_name, attr_last_name, size_limit, time_limit_seconds, last_test_at, last_test_outcome, created_by, updated_by, created_at, updated_at"

func scanDirectoryConnection(r pgx.Row) (DirectoryConnection, error) {
	var c DirectoryConnection
	err := r.Scan(&c.ID, &c.TenantID, &c.Name, &c.Kind, &c.URL, &c.TLSMode, &c.AllowTLS12, &c.CAPEM, &c.BindDN, &c.BindPasswordEnc,
		&c.BaseDN, &c.BaseFilter, &c.AttrUID, &c.AttrEmail, &c.AttrDisplayName, &c.AttrFirstName, &c.AttrLastName,
		&c.SizeLimit, &c.TimeLimitSeconds, &c.LastTestAt, &c.LastTestOutcome, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, notFound(err)
}

// InsertDirectoryConnection creates a connection; a duplicate name
// (case-insensitive, per tenant) is ErrConflict.
func InsertDirectoryConnection(ctx context.Context, tx pgx.Tx, c DirectoryConnection) error {
	_, err := tx.Exec(ctx, `INSERT INTO directory_connections (id, tenant_id, name, kind, url, tls_mode, allow_tls12, ca_pem, bind_dn, bind_password_enc,
		base_dn, base_filter, attr_uid, attr_email, attr_display_name, attr_first_name, attr_last_name, size_limit, time_limit_seconds, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NULLIF($20,'')::uuid,NULLIF($20,'')::uuid)`,
		c.ID, c.TenantID, c.Name, c.Kind, c.URL, c.TLSMode, c.AllowTLS12, c.CAPEM, c.BindDN, c.BindPasswordEnc,
		c.BaseDN, c.BaseFilter, c.AttrUID, c.AttrEmail, c.AttrDisplayName, c.AttrFirstName, c.AttrLastName, c.SizeLimit, c.TimeLimitSeconds,
		deref(c.CreatedBy))
	return conflict(err)
}

// GetDirectoryConnection by tenant + id.
func GetDirectoryConnection(ctx context.Context, tx pgx.Tx, tenantID, id string) (DirectoryConnection, error) {
	return scanDirectoryConnection(tx.QueryRow(ctx, "SELECT "+dirConnCols+" FROM directory_connections WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// GetDirectoryConnectionAnyTenant by id alone (system scope; cross-tenant
// refusal auditing only).
func GetDirectoryConnectionAnyTenant(ctx context.Context, tx pgx.Tx, id string) (DirectoryConnection, error) {
	return scanDirectoryConnection(tx.QueryRow(ctx, "SELECT "+dirConnCols+" FROM directory_connections WHERE id = $1", id))
}

// ListDirectoryConnections of a tenant, by name.
func ListDirectoryConnections(ctx context.Context, tx pgx.Tx, tenantID string) ([]DirectoryConnection, error) {
	rows, err := tx.Query(ctx, "SELECT "+dirConnCols+" FROM directory_connections WHERE tenant_id = $1 ORDER BY lower(name), id", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryConnection
	for rows.Next() {
		c, err := scanDirectoryConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountDirectoryConnections of a tenant (max_connections_per_tenant cap).
func CountDirectoryConnections(ctx context.Context, tx pgx.Tx, tenantID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, "SELECT count(*) FROM directory_connections WHERE tenant_id = $1", tenantID).Scan(&n)
	return n, err
}

// UpdateDirectoryConnection rewrites the editable fields. An empty
// BindPasswordEnc keeps the stored password (optional on update). Test state,
// creator and creation time are untouched.
func UpdateDirectoryConnection(ctx context.Context, tx pgx.Tx, c DirectoryConnection) error {
	var pw []byte // nil → keep
	if len(c.BindPasswordEnc) > 0 {
		pw = c.BindPasswordEnc
	}
	ct, err := tx.Exec(ctx, `UPDATE directory_connections SET name = $3, kind = $4, url = $5, tls_mode = $6, allow_tls12 = $7, ca_pem = NULLIF($8,''),
		bind_dn = $9, bind_password_enc = COALESCE($10, bind_password_enc), base_dn = $11, base_filter = $12, attr_uid = $13, attr_email = $14,
		attr_display_name = $15, attr_first_name = $16, attr_last_name = $17, size_limit = $18, time_limit_seconds = $19,
		updated_by = NULLIF($20,'')::uuid, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		c.TenantID, c.ID, c.Name, c.Kind, c.URL, c.TLSMode, c.AllowTLS12, c.CAPEM,
		c.BindDN, pw, c.BaseDN, c.BaseFilter, c.AttrUID, c.AttrEmail,
		c.AttrDisplayName, c.AttrFirstName, c.AttrLastName, c.SizeLimit, c.TimeLimitSeconds,
		deref(c.UpdatedBy))
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDirectoryConnectionTest records the outcome of a connection test.
func SetDirectoryConnectionTest(ctx context.Context, tx pgx.Tx, tenantID, id, outcome string, at time.Time) error {
	ct, err := tx.Exec(ctx, "UPDATE directory_connections SET last_test_at = $3, last_test_outcome = $4 WHERE tenant_id = $1 AND id = $2", tenantID, id, at, outcome)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteDirectoryConnection removes a connection; links keep their
// connection_name snapshot (connection_id is set NULL by the FK).
func DeleteDirectoryConnection(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM directory_connections WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- import support

// UsersByEmails returns the tenant's users for the given e-mails, keyed by
// the stored e-mail (preview status). Matching is case-insensitive (citext);
// unknown e-mails are absent from the map.
func UsersByEmails(ctx context.Context, tx pgx.Tx, tenantID string, emails []string) (map[string]User, error) {
	out := make(map[string]User, len(emails))
	if len(emails) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, "SELECT "+userCols+" FROM users WHERE tenant_id = $1 AND email = ANY($2::text[]::citext[])", tenantID, emails)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out[u.Email] = u
	}
	return out, rows.Err()
}

const linkCols = "user_id, tenant_id, connection_id, connection_name, directory_uid, directory_dn, first_imported_at, last_imported_at, imported_by"

func scanLink(r pgx.Row) (DirectoryLink, error) {
	var l DirectoryLink
	err := r.Scan(&l.UserID, &l.TenantID, &l.ConnectionID, &l.ConnectionName, &l.DirectoryUID, &l.DirectoryDN, &l.FirstImportedAt, &l.LastImportedAt, &l.ImportedBy)
	return l, notFound(err)
}

// LinksByUIDs returns the links of one connection for the given directory
// uids, keyed by uid (the idempotency lookup).
func LinksByUIDs(ctx context.Context, tx pgx.Tx, tenantID, connID string, uids []string) (map[string]DirectoryLink, error) {
	out := make(map[string]DirectoryLink, len(uids))
	if len(uids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, "SELECT "+linkCols+" FROM user_directory_links WHERE tenant_id = $1 AND connection_id = $2 AND directory_uid = ANY($3)", tenantID, connID, uids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out[l.DirectoryUID] = l
	}
	return out, rows.Err()
}

// UpsertLink inserts a user's link or refreshes it on re-import
// (first_imported_at is kept). A uid already linked to another user of the
// same connection is ErrConflict.
func UpsertLink(ctx context.Context, tx pgx.Tx, l DirectoryLink) error {
	_, err := tx.Exec(ctx, `INSERT INTO user_directory_links (`+linkCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::uuid)
		ON CONFLICT (user_id) DO UPDATE SET connection_id = EXCLUDED.connection_id, connection_name = EXCLUDED.connection_name,
			directory_uid = EXCLUDED.directory_uid, directory_dn = EXCLUDED.directory_dn,
			last_imported_at = EXCLUDED.last_imported_at, imported_by = EXCLUDED.imported_by`,
		l.UserID, l.TenantID, l.ConnectionID, l.ConnectionName, l.DirectoryUID, l.DirectoryDN, l.FirstImportedAt, l.LastImportedAt, deref(l.ImportedBy))
	return conflict(err)
}

// UpdateImportedUser refreshes e-mail and names of a user that is still
// imported; any other status (or a missing user) is ErrNotFound, and an
// e-mail already used in the tenant is ErrConflict.
func UpdateImportedUser(ctx context.Context, tx pgx.Tx, tenantID, userID string, p ImportedProfile) error {
	ct, err := tx.Exec(ctx, `UPDATE users SET email = $3, display_name = $4, first_name = $5, last_name = $6, display_name_explicit = $7, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND status = 'imported'`,
		tenantID, userID, p.Email, p.DisplayName, p.FirstName, p.LastName, p.DisplayNameExplicit)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteImportedUser hard-deletes a user only while imported (the link
// cascades); any other status (or a missing user) is ErrNotFound.
func DeleteImportedUser(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM users WHERE tenant_id = $1 AND id = $2 AND status = 'imported'", tenantID, userID)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
