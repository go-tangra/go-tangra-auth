package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------- security keys (feature 018)

// WebAuthnCredential is one registered security key. The public key and
// credential id are integrity-critical but not secret; they are never logged
// or audited (audit names the row id only).
type WebAuthnCredential struct {
	ID, TenantID, UserID    string
	CredentialID, PublicKey []byte
	AAGUID                  []byte
	SignCount               int64
	Transports              []string
	BackupEligible          bool
	BackupState             bool
	Name                    string
	CreatedAt               time.Time
	LastUsedAt              *time.Time
	CloneFlaggedAt          *time.Time
}

// ErrCredentialExists refuses a credential id that is already registered.
var ErrCredentialExists = errors.New("store: credential already registered")

const webauthnCols = "id, tenant_id, user_id, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, name, created_at, last_used_at, clone_flagged_at"

// InsertWebAuthnCredential stores a key. A taken credential id is
// ErrCredentialExists; a name the user already uses is ErrConflict.
func InsertWebAuthnCredential(ctx context.Context, tx pgx.Tx, c WebAuthnCredential) error { //nolint:gocritic // row value, mirrors the other Insert* functions
	transports := c.Transports
	if transports == nil {
		transports = []string{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO webauthn_credentials (id, tenant_id, user_id, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		c.ID, c.TenantID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.AAGUID, transports, c.BackupEligible, c.BackupState, c.Name)
	return webauthnUnique(err)
}

func webauthnUnique(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		if pg.ConstraintName == "webauthn_credentials_credential_id_key" {
			return ErrCredentialExists
		}
		return ErrConflict
	}
	return err
}

// ListWebAuthnCredentials returns a user's keys, oldest first.
func ListWebAuthnCredentials(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]WebAuthnCredential, error) {
	rows, err := tx.Query(ctx, "SELECT "+webauthnCols+" FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at, id", tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.AAGUID, &c.Transports,
			&c.BackupEligible, &c.BackupState, &c.Name, &c.CreatedAt, &c.LastUsedAt, &c.CloneFlaggedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountAllWebAuthnCredentials counts keys across tenants (system scope; the
// start-up warning when keys are disabled but registered).
func CountAllWebAuthnCredentials(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	err := tx.QueryRow(ctx, "SELECT count(*) FROM webauthn_credentials").Scan(&n)
	return n, err
}

// RenameWebAuthnCredential renames one of the user's keys.
func RenameWebAuthnCredential(ctx context.Context, tx pgx.Tx, tenantID, userID, id, name string) error {
	ct, err := tx.Exec(ctx, "UPDATE webauthn_credentials SET name = $4 WHERE tenant_id = $1 AND user_id = $2 AND id = $3", tenantID, userID, id, name)
	if err != nil {
		return webauthnUnique(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebAuthnCredential removes one of the user's keys.
func DeleteWebAuthnCredential(ctx context.Context, tx pgx.Tx, tenantID, userID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3", tenantID, userID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// UpdateWebAuthnUse records a successful assertion: the new signature
// counter, the backup state the authenticator reported and the time.
func UpdateWebAuthnUse(ctx context.Context, tx pgx.Tx, tenantID, id string, signCount int64, backupState bool) error {
	ct, err := tx.Exec(ctx, "UPDATE webauthn_credentials SET sign_count = $3, backup_state = $4, last_used_at = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, signCount, backupState)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// FlagWebAuthnClone marks a key as possibly cloned; flagged keys are refused
// until removed.
func FlagWebAuthnClone(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "UPDATE webauthn_credentials SET clone_flagged_at = COALESCE(clone_flagged_at, now()) WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// WebAuthnHandle returns the user's WebAuthn user handle, nil before the
// first registration.
func WebAuthnHandle(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]byte, error) {
	var h []byte
	err := tx.QueryRow(ctx, "SELECT webauthn_handle FROM users WHERE tenant_id = $1 AND id = $2", tenantID, userID).Scan(&h)
	return h, notFound(err)
}

// EnsureWebAuthnHandle sets the user handle to candidate unless one exists
// and returns the stored handle (created once, stable afterwards).
func EnsureWebAuthnHandle(ctx context.Context, tx pgx.Tx, tenantID, userID string, candidate []byte) ([]byte, error) {
	var h []byte
	err := tx.QueryRow(ctx, "UPDATE users SET webauthn_handle = COALESCE(webauthn_handle, $3) WHERE tenant_id = $1 AND id = $2 RETURNING webauthn_handle",
		tenantID, userID, candidate).Scan(&h)
	return h, notFound(err)
}

// ResetMFA removes every second factor of a user (administrator reset): the
// TOTP seed and counter, recovery codes and security keys; the account no
// longer asks for a second step.
func ResetMFA(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	ct, err := tx.Exec(ctx, "UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_last_counter = 0, updated_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := ReplaceRecoveryCodes(ctx, tx, tenantID, userID, nil); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "DELETE FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2", tenantID, userID)
	return err
}
