package enrollment

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type enrollmentRepository struct{ executor sqlExecutor }

func (repository enrollmentRepository) ByTokenHash(ctx context.Context, tokenHash string) (domainenrollment.Enrollment, error) {
	var raw []byte
	err := repository.executor.QueryRowContext(ctx, `SELECT data FROM enrollments WHERE token_hash=$1 ORDER BY created_at DESC LIMIT 1`, tokenHash).Scan(&raw)
	if err == sql.ErrNoRows {
		return domainenrollment.Enrollment{}, failure.New(failure.NotFound, "enrollment not found")
	}
	if err != nil {
		return domainenrollment.Enrollment{}, fmt.Errorf("query enrollment by token: %w", err)
	}
	return decodeEnrollment(raw)
}

func (repository enrollmentRepository) Put(ctx context.Context, value domainenrollment.Enrollment) error {
	raw, err := encodeEnrollment(value)
	if err != nil {
		return err
	}
	result, err := repository.executor.ExecContext(ctx, `INSERT INTO enrollments
(tenant_id,enrollment_id,agent_id,token_hash,status,created_at,expires_at,used_at,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (tenant_id,enrollment_id) DO UPDATE SET agent_id=excluded.agent_id,token_hash=excluded.token_hash,
status=excluded.status,expires_at=excluded.expires_at,used_at=excluded.used_at,data=excluded.data
WHERE enrollments.status='active' OR enrollments.data=excluded.data`, value.TenantID.String(), value.ID,
		value.AgentID, value.TokenHash, string(value.Status), value.CreatedAt, optionalTime(value.ExpiresAt), optionalTime(value.UsedAt), raw)
	if err != nil {
		return fmt.Errorf("put enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read enrollment write result: %w", err)
	}
	if rows != 1 {
		return failure.New(failure.Conflict, "enrollment was concurrently changed")
	}
	return nil
}

type certificateRepository struct{ executor sqlExecutor }

func (repository certificateRepository) Put(ctx context.Context, value domainenrollment.Certificate) error {
	raw, err := encodeCertificate(value)
	if err != nil {
		return err
	}
	_, err = repository.executor.ExecContext(ctx, `INSERT INTO agent_certificates
(tenant_id,agent_id,serial_number,enrollment_id,not_before,not_after,created_at,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id,serial_number) DO UPDATE SET agent_id=excluded.agent_id,enrollment_id=excluded.enrollment_id,
not_before=excluded.not_before,not_after=excluded.not_after,data=excluded.data`, value.TenantID.String(), value.AgentID,
		value.SerialNumber, value.EnrollmentID, optionalTime(value.NotBefore), optionalTime(value.NotAfter), value.CreatedAt, raw)
	if err != nil {
		return fmt.Errorf("put agent certificate: %w", err)
	}
	return nil
}

func optionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
