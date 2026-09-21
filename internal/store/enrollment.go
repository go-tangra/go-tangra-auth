package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConsumeEnrollmentJTI records an lcm enrollment token's JTI as used, enforcing
// single-use. The first call for a JTI succeeds; any later call returns
// ErrConflict, so a captured or replayed enrollment token can be used at most
// once.
func ConsumeEnrollmentJTI(ctx context.Context, tx pgx.Tx, jti, tenantID string, expiresAt time.Time) error {
	ct, err := tx.Exec(ctx, "INSERT INTO enrollment_jti (jti, tenant_id, expires_at) VALUES ($1,$2,$3) ON CONFLICT (jti) DO NOTHING", jti, tenantID, expiresAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}
