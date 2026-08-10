package response

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type repository struct{ db responseSQLExecutor }

func (repo repository) Create(ctx context.Context, value domainresponse.Command) (domainresponse.Command, error) {
	document, err := encodeCommand(value)
	if err != nil {
		return domainresponse.Command{}, err
	}
	result, err := repo.db.ExecContext(ctx, `INSERT INTO response_audit
(tenant_id,response_id,agent_id,status,action,created_at,updated_at,command,ack)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL) ON CONFLICT (tenant_id,response_id) DO NOTHING`,
		value.TenantID.String(), value.ID, value.AgentID, string(value.Status), value.Action,
		value.CreatedAt, value.UpdatedAt, document)
	if err != nil {
		return domainresponse.Command{}, fmt.Errorf("create response command: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return domainresponse.Command{}, fmt.Errorf("create response command rows: %w", err)
	}
	if count == 0 {
		return repo.Get(ctx, value.TenantID, value.ID)
	}
	return value, nil
}

func (repo repository) Get(ctx context.Context, tenantID tenant.ID, id string) (domainresponse.Command, error) {
	if tenantID.IsZero() || id == "" {
		return domainresponse.Command{}, failure.New(failure.InvalidArgument, "response command identity is required")
	}
	var command, ack []byte
	err := repo.db.QueryRowContext(ctx, `SELECT command,ack FROM response_audit WHERE tenant_id=$1 AND response_id=$2`,
		tenantID.String(), id).Scan(&command, &ack)
	if err == sql.ErrNoRows {
		return domainresponse.Command{}, failure.New(failure.NotFound, "response command not found")
	}
	if err != nil {
		return domainresponse.Command{}, fmt.Errorf("get response command: %w", err)
	}
	return decodeCommand(command, ack)
}

func (repo repository) List(ctx context.Context, tenantID tenant.ID, filter ports.ResponseFilter) ([]domainresponse.Command, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT command,ack FROM response_audit
WHERE tenant_id=$1 AND ($2='' OR agent_id=$2) AND ($3=FALSE OR (status='pending' AND ack IS NULL))
ORDER BY created_at`, tenantID.String(), filter.AgentID, filter.Pending)
	if err != nil {
		return nil, fmt.Errorf("list response commands: %w", err)
	}
	defer rows.Close()
	var values []domainresponse.Command
	for rows.Next() {
		var command, ack []byte
		if err := rows.Scan(&command, &ack); err != nil {
			return nil, fmt.Errorf("scan response command: %w", err)
		}
		value, err := decodeCommand(command, ack)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (repo repository) Put(ctx context.Context, current, next domainresponse.Command) error {
	expectedCommand, err := encodeCommand(current)
	if err != nil {
		return err
	}
	expectedAck, err := encodeAcknowledgement(current.ID, current.Ack)
	if err != nil {
		return err
	}
	command, err := encodeCommand(next)
	if err != nil {
		return err
	}
	ack, err := encodeAcknowledgement(next.ID, next.Ack)
	if err != nil {
		return err
	}
	result, err := repo.db.ExecContext(ctx, `UPDATE response_audit SET
agent_id=$1,status=$2,action=$3,updated_at=$4,command=$5,ack=$6
WHERE tenant_id=$7 AND response_id=$8 AND command=$9
AND (($10 IS NULL AND ack IS NULL) OR ack=$10)`, next.AgentID, string(next.Status), next.Action,
		next.UpdatedAt, command, ack, current.TenantID.String(), current.ID, expectedCommand, expectedAck)
	if err != nil {
		return fmt.Errorf("put response command: %w", err)
	}
	return requireAffected(result, "response command changed concurrently")
}

type auditRepository struct{ db responseSQLExecutor }

func (repo auditRepository) Append(ctx context.Context, value domainresponse.AuditRecord) error {
	document, err := encodeAudit(value)
	if err != nil {
		return err
	}
	_, err = repo.db.ExecContext(ctx, `INSERT INTO response_decisions
(tenant_id,audit_id,response_id,action,actor,role,approved,reason,status,created_at,data)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, value.TenantID.String(), value.ID, value.ResponseID,
		value.Action, value.Actor, value.Role, value.Approved, value.Reason, string(value.Status), value.OccurredAt, document)
	if err != nil {
		return fmt.Errorf("append response audit: %w", err)
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
