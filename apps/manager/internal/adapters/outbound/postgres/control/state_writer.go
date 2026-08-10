package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

type StateWriter struct{ db *sql.DB }

func NewStateWriter(db *sql.DB) StateWriter { return StateWriter{db: db} }
func (writer StateWriter) RecordHealth(ctx context.Context, value domainidentity.Health) error {
	if value.TenantID.IsZero() || value.AgentID == "" {
		return fmt.Errorf("health identity is required")
	}
	document := value.Document
	if len(document) == 0 {
		document, _ = json.Marshal(value)
	}
	observed := value.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	_, err := writer.db.ExecContext(ctx, `INSERT INTO agent_health (tenant_id,agent_id,host_id,scope_type,scope_selector,observed_at,data) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,agent_id) DO UPDATE SET host_id=EXCLUDED.host_id,scope_type=EXCLUDED.scope_type,scope_selector=EXCLUDED.scope_selector,observed_at=EXCLUDED.observed_at,data=EXCLUDED.data`, value.TenantID.String(), string(value.AgentID), value.HostID, value.Scope.Type, value.Scope.Selector, observed, document)
	if err != nil {
		return fmt.Errorf("record agent health: %w", err)
	}
	return nil
}
func (writer StateWriter) RecordCapability(ctx context.Context, value domaingateway.Capability) error {
	document, _ := json.Marshal(value)
	result, err := writer.db.ExecContext(ctx, `INSERT INTO agents (tenant_id,agent_id,host_id,version,data) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,agent_id) DO UPDATE SET host_id=EXCLUDED.host_id,version=EXCLUDED.version,observed_at=now(),data=EXCLUDED.data`, value.TenantID, value.AgentID, value.HostID, value.Version, document)
	return affected(result, err, "record agent capability")
}
func (writer StateWriter) AckResponse(ctx context.Context, value domaingateway.Ack) error {
	document, _ := json.Marshal(value)
	result, err := writer.db.ExecContext(ctx, `UPDATE response_audit SET status=$4,updated_at=now(),ack=$5 WHERE tenant_id=$1 AND agent_id=$2 AND response_id=$3`, value.TenantID, value.AgentID, value.ID, value.Status, document)
	return affected(result, err, "ack response")
}
func (writer StateWriter) AckCommand(ctx context.Context, value domaingateway.Ack) error {
	result, err := writer.db.ExecContext(ctx, `UPDATE control_commands SET status=$4,acked_at=now(),updated_at=now(),data=jsonb_set(data,'{status}',to_jsonb($4::text),true) WHERE tenant_id=$1 AND agent_id=$2 AND command_id=$3`, value.TenantID, value.AgentID, value.ID, value.Status)
	return affected(result, err, "ack control command")
}
func (writer StateWriter) CompleteEvidence(ctx context.Context, value domaingateway.EvidenceResult) error {
	status := "failed"
	if value.OK {
		status = "completed"
	}
	document, _ := json.Marshal(value)
	result, err := writer.db.ExecContext(ctx, `UPDATE evidence_pullbacks SET status=$4,updated_at=now(),data=$5 WHERE tenant_id=$1 AND agent_id=$2 AND request_id=$3`, value.TenantID, value.AgentID, value.RequestID, status, document)
	return affected(result, err, "complete evidence pullback")
}
func affected(result sql.Result, err error, operation string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows: %w", operation, err)
	}
	if count == 0 {
		return fmt.Errorf("%s target not found", operation)
	}
	return nil
}
