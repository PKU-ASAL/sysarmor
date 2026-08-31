package policy

import (
	"context"
	"database/sql"
	"fmt"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type SnapshotOutbox struct{ db *sql.DB }

func NewSnapshotOutbox(db *sql.DB) *SnapshotOutbox { return &SnapshotOutbox{db: db} }

func (outbox *SnapshotOutbox) Pending(ctx context.Context, limit int) ([]ports.PolicySnapshot, error) {
	rows, err := outbox.db.QueryContext(ctx, `SELECT tenant_id,policy_id,policy_version,policy_document FROM policy_snapshot_outbox WHERE published_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ports.PolicySnapshot
	for rows.Next() {
		var tenantValue, policyID string
		var version uint64
		var document []byte
		if err := rows.Scan(&tenantValue, &policyID, &version, &document); err != nil {
			return nil, err
		}
		tenantID, err := tenant.NewID(tenantValue)
		if err != nil {
			return nil, err
		}
		items = append(items, ports.PolicySnapshot{TenantID: tenantID, PolicyID: domainpolicy.ID(policyID), Version: domainpolicy.Version(version), Document: document})
	}
	return items, rows.Err()
}

func (outbox *SnapshotOutbox) MarkPublished(ctx context.Context, item ports.PolicySnapshot) error {
	_, err := outbox.db.ExecContext(ctx, `UPDATE policy_snapshot_outbox SET published_at=now(),attempt_count=attempt_count+1,last_error='' WHERE tenant_id=$1 AND policy_id=$2 AND policy_version=$3`, item.TenantID.String(), item.PolicyID.String(), uint64(item.Version))
	return err
}

func (outbox *SnapshotOutbox) RecordFailure(ctx context.Context, item ports.PolicySnapshot, message string) error {
	_, err := outbox.db.ExecContext(ctx, `UPDATE policy_snapshot_outbox SET attempt_count=attempt_count+1,last_error=$4 WHERE tenant_id=$1 AND policy_id=$2 AND policy_version=$3`, item.TenantID.String(), item.PolicyID.String(), uint64(item.Version), message)
	if err != nil {
		return fmt.Errorf("record policy snapshot failure: %w", err)
	}
	return nil
}
