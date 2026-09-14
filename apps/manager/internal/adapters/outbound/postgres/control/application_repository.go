package control

import (
	"context"
	"database/sql"
	"fmt"

	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type commandRepository struct{ db controlSQLExecutor }

func (repo commandRepository) Create(ctx context.Context, value domaincontrol.Command) (domaincontrol.Command, error) {
	document, err := encodeCommand(value)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	result, err := repo.db.ExecContext(ctx, `INSERT INTO control_commands
(tenant_id,command_id,agent_id,command_type,status,policy_id,policy_version,content_ref,content_kind,content_version,actor,reason,created_at,updated_at,attempt_count,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (tenant_id,command_id) DO NOTHING`,
		value.TenantID.String(), value.ID, value.AgentID, string(value.Type), string(value.Status), value.PolicyID,
		value.PolicyVersion, value.ContentRef, value.ContentKind, value.ContentVersion, value.Actor, value.Reason,
		value.CreatedAt, value.UpdatedAt, value.AttemptCount, document)
	if err != nil {
		return domaincontrol.Command{}, fmt.Errorf("create control command: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return domaincontrol.Command{}, fmt.Errorf("create control command rows: %w", err)
	}
	if count == 0 {
		return repo.Get(ctx, value.TenantID, value.ID)
	}
	return value, nil
}

func (repo commandRepository) Get(ctx context.Context, tenantID tenant.ID, id string) (domaincontrol.Command, error) {
	if tenantID.IsZero() || id == "" {
		return domaincontrol.Command{}, failure.New(failure.InvalidArgument, "control command identity is required")
	}
	var document []byte
	err := repo.db.QueryRowContext(ctx, `SELECT data FROM control_commands WHERE tenant_id=$1 AND command_id=$2`, tenantID.String(), id).Scan(&document)
	if err == sql.ErrNoRows {
		return domaincontrol.Command{}, failure.New(failure.NotFound, "control command not found")
	}
	if err != nil {
		return domaincontrol.Command{}, fmt.Errorf("get control command: %w", err)
	}
	return decodeCommand(document)
}

func (repo commandRepository) List(ctx context.Context, tenantID tenant.ID, filter ports.ControlFilter) ([]domaincontrol.Command, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT data FROM control_commands
WHERE tenant_id=$1 AND ($2='' OR agent_id=$2) AND ($3='' OR command_type=$3) ORDER BY created_at`,
		tenantID.String(), filter.AgentID, string(filter.Type))
	if err != nil {
		return nil, fmt.Errorf("list control commands: %w", err)
	}
	defer rows.Close()
	var values []domaincontrol.Command
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan control command: %w", err)
		}
		value, err := decodeCommand(document)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate control commands: %w", err)
	}
	return values, nil
}

func (repo commandRepository) Put(ctx context.Context, current, next domaincontrol.Command) error {
	document, err := encodeCommand(next)
	if err != nil {
		return err
	}
	expected, err := encodeCommand(current)
	if err != nil {
		return err
	}
	result, err := repo.db.ExecContext(ctx, `UPDATE control_commands SET
agent_id=$1,command_type=$2,status=$3,policy_id=$4,policy_version=$5,content_ref=$6,
content_kind=$7,content_version=$8,actor=$9,reason=$10,updated_at=$11,sent_at=$12,last_sent_at=$13,
acked_at=$14,canceled_at=$15,expired_at=$16,attempt_count=$17,data=$18
WHERE tenant_id=$19 AND command_id=$20 AND data=$21`,
		next.AgentID, string(next.Type), string(next.Status), next.PolicyID, next.PolicyVersion,
		next.ContentRef, next.ContentKind, next.ContentVersion, next.Actor, next.Reason, next.UpdatedAt,
		nullTime(next.SentAt), nullTime(next.LastSentAt), nullTime(next.AckedAt), nullTime(next.CanceledAt),
		nullTime(next.ExpiredAt), next.AttemptCount, document, current.TenantID.String(), current.ID, expected)
	if err != nil {
		return fmt.Errorf("put control command: %w", err)
	}
	return requireAffected(result, "control command changed concurrently")
}

type evidenceRepository struct{ db controlSQLExecutor }

func (repo evidenceRepository) Create(ctx context.Context, value domaincontrol.EvidencePullback) (domaincontrol.EvidencePullback, error) {
	document, err := encodeEvidence(value)
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	result, err := repo.db.ExecContext(ctx, `INSERT INTO evidence_pullbacks
(tenant_id,request_id,agent_id,incident_id,status,created_at,updated_at,data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id,request_id) DO NOTHING`, value.TenantID.String(), value.ID, value.AgentID,
		value.IncidentID, string(value.Status), value.CreatedAt, value.UpdatedAt, document)
	if err != nil {
		return domaincontrol.EvidencePullback{}, fmt.Errorf("create evidence pullback: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return domaincontrol.EvidencePullback{}, fmt.Errorf("create evidence pullback rows: %w", err)
	}
	if count == 0 {
		return repo.Get(ctx, value.TenantID, value.ID)
	}
	return value, nil
}

func (repo evidenceRepository) Get(ctx context.Context, tenantID tenant.ID, id string) (domaincontrol.EvidencePullback, error) {
	if tenantID.IsZero() || id == "" {
		return domaincontrol.EvidencePullback{}, failure.New(failure.InvalidArgument, "evidence pullback identity is required")
	}
	var document []byte
	err := repo.db.QueryRowContext(ctx, `SELECT data FROM evidence_pullbacks WHERE tenant_id=$1 AND request_id=$2`, tenantID.String(), id).Scan(&document)
	if err == sql.ErrNoRows {
		return domaincontrol.EvidencePullback{}, failure.New(failure.NotFound, "evidence pullback not found")
	}
	if err != nil {
		return domaincontrol.EvidencePullback{}, fmt.Errorf("get evidence pullback: %w", err)
	}
	return decodeEvidence(document)
}

func (repo evidenceRepository) List(ctx context.Context, tenantID tenant.ID, filter ports.EvidenceFilter) ([]domaincontrol.EvidencePullback, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT data FROM evidence_pullbacks
WHERE tenant_id=$1 AND ($2='' OR agent_id=$2) ORDER BY created_at`, tenantID.String(), filter.AgentID)
	if err != nil {
		return nil, fmt.Errorf("list evidence pullbacks: %w", err)
	}
	defer rows.Close()
	var values []domaincontrol.EvidencePullback
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan evidence pullback: %w", err)
		}
		value, err := decodeEvidence(document)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evidence pullbacks: %w", err)
	}
	return values, nil
}

func (repo evidenceRepository) Put(ctx context.Context, current, next domaincontrol.EvidencePullback) error {
	document, err := encodeEvidence(next)
	if err != nil {
		return err
	}
	expected, err := encodeEvidence(current)
	if err != nil {
		return err
	}
	result, err := repo.db.ExecContext(ctx, `UPDATE evidence_pullbacks SET
agent_id=$1,incident_id=$2,status=$3,updated_at=$4,data=$5
WHERE tenant_id=$6 AND request_id=$7 AND data=$8`, next.AgentID, next.IncidentID, string(next.Status),
		next.UpdatedAt, document, current.TenantID.String(), current.ID, expected)
	if err != nil {
		return fmt.Errorf("put evidence pullback: %w", err)
	}
	return requireAffected(result, "evidence pullback changed concurrently")
}

type auditRepository struct{ db controlSQLExecutor }

func (repo auditRepository) Append(ctx context.Context, value domaincontrol.AuditRecord) error {
	document, err := encodeAudit(value)
	if err != nil {
		return err
	}
	_, err = repo.db.ExecContext(ctx, `INSERT INTO control_audit
(tenant_id,audit_id,resource_id,action,actor,reason,status,created_at,data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, value.TenantID.String(), value.ID, value.ResourceID,
		value.Action, value.Actor, value.Reason, value.Status, value.OccurredAt, document)
	if err != nil {
		return fmt.Errorf("append control audit: %w", err)
	}
	return nil
}

func requireAffected(result sql.Result, message string) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected rows: %w", err)
	}
	if count == 0 {
		return failure.New(failure.Conflict, message)
	}
	return nil
}

func nullTime(value interface{ IsZero() bool }) any {
	if value.IsZero() {
		return nil
	}
	return value
}
