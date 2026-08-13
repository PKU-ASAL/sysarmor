package identity

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type CertificateAuthorizer struct{ db *sql.DB }

func NewCertificateAuthorizer(db *sql.DB) CertificateAuthorizer { return CertificateAuthorizer{db: db} }
func (authorizer CertificateAuthorizer) Authorize(ctx context.Context, tenantID, agentID, serial string) error {
	var storedAgent string
	var revoked sql.NullTime
	err := authorizer.db.QueryRowContext(ctx, `SELECT agent_id, revoked_at FROM agent_certificates WHERE tenant_id=$1 AND serial_number=$2`, tenantID, serial).Scan(&storedAgent, &revoked)
	if err == sql.ErrNoRows {
		return failure.New(failure.PermissionDenied, "agent certificate is not registered")
	}
	if err != nil {
		return fmt.Errorf("read agent certificate: %w", err)
	}
	if storedAgent != agentID {
		return failure.New(failure.PermissionDenied, "agent certificate identity mismatch")
	}
	if revoked.Valid {
		return failure.New(failure.PermissionDenied, "agent certificate is revoked")
	}
	return nil
}
