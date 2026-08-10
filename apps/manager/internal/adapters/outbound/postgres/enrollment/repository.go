package enrollment

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
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

type unenrollmentRepository struct{ executor sqlExecutor }

func (repository unenrollmentRepository) Get(ctx context.Context, tenantID tenant.ID, enrollmentID string) (domainenrollment.Unenrollment, error) {
	if tenantID == "" {
		return domainenrollment.Unenrollment{}, failure.New(failure.InvalidArgument, "tenant is required")
	}
	var raw []byte
	err := repository.executor.QueryRowContext(ctx,
		`SELECT data FROM agent_unenrollments WHERE tenant_id=$1 AND enrollment_id=$2`, tenantID.String(), enrollmentID).Scan(&raw)
	if err == sql.ErrNoRows {
		return domainenrollment.Unenrollment{}, failure.New(failure.NotFound, "unenrollment not found")
	}
	if err != nil {
		return domainenrollment.Unenrollment{}, fmt.Errorf("get unenrollment: %w", err)
	}
	return decodeUnenrollment(raw)
}

func (repository unenrollmentRepository) Put(ctx context.Context, value domainenrollment.Unenrollment) error {
	raw, err := encodeUnenrollment(value)
	if err != nil {
		return err
	}
	_, err = repository.executor.ExecContext(ctx, `INSERT INTO agent_unenrollments
(tenant_id,enrollment_id,agent_id,certificate_serial,status,revoked_at,endpoint_completed_at,created_at,updated_at,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (tenant_id,enrollment_id) DO UPDATE SET status=excluded.status,
endpoint_completed_at=excluded.endpoint_completed_at,updated_at=excluded.updated_at,data=excluded.data`,
		value.Identity.TenantID.String(), value.Identity.EnrollmentID, value.Identity.AgentID,
		value.Identity.CertificateSerial, string(value.Status), value.RevokedAt, optionalTime(value.CompletedAt),
		value.RevokedAt, unenrollmentUpdatedAt(value), raw)
	if err != nil {
		return fmt.Errorf("put unenrollment: %w", err)
	}
	return nil
}

func unenrollmentUpdatedAt(value domainenrollment.Unenrollment) time.Time {
	if !value.CompletedAt.IsZero() {
		return value.CompletedAt
	}
	return value.RevokedAt
}
