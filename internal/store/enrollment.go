package store

import (
	"context"
	"errors"
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

// EnrollmentJTIConsumedAt reports whether an enrollment token's JTI has been
// consumed (burned by ConsumeEnrollmentJTI) and when. An unknown JTI, including
// one pruned after its token expired, is (zero, false, nil). jti must be a
// UUID; the caller validates it.
func EnrollmentJTIConsumedAt(ctx context.Context, tx pgx.Tx, jti string) (time.Time, bool, error) {
	var at time.Time
	err := tx.QueryRow(ctx, "SELECT consumed_at FROM enrollment_jti WHERE jti = $1", jti).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return at, true, nil
}
