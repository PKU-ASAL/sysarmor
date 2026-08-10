package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type HealthWriter struct{ db *sql.DB }

func NewHealthWriter(db *sql.DB) ports.AgentHealthWriter { return HealthWriter{db: db} }

func (writer HealthWriter) Upsert(ctx context.Context, health domainidentity.Health) error {
	if err := requireTenant(health.TenantID); err != nil {
		return err
	}
	if health.AgentID == "" {
		return fmt.Errorf("agent health identity is required")
	}
	document, err := healthDocument(health)
	if err != nil {
		return err
	}
	observed := health.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	_, err = writer.db.ExecContext(ctx, `INSERT INTO agent_health (tenant_id,agent_id,host_id,scope_type,scope_selector,observed_at,data) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,agent_id) DO UPDATE SET host_id=EXCLUDED.host_id,scope_type=EXCLUDED.scope_type,scope_selector=EXCLUDED.scope_selector,observed_at=EXCLUDED.observed_at,data=EXCLUDED.data`, health.TenantID.String(), string(health.AgentID), health.HostID, health.Scope.Type, health.Scope.Selector, observed, document)
	if err != nil {
		return fmt.Errorf("upsert agent health: %w", err)
	}
	return nil
}

func healthDocument(health domainidentity.Health) ([]byte, error) {
	fields := map[string]json.RawMessage{}
	if len(health.Document) > 0 {
		if err := json.Unmarshal(health.Document, &fields); err != nil {
			return nil, fmt.Errorf("decode agent health document: %w", err)
		}
	}
	tenantID, err := json.Marshal(health.TenantID.String())
	if err != nil {
		return nil, fmt.Errorf("encode agent health tenant: %w", err)
	}
	agentID, err := json.Marshal(string(health.AgentID))
	if err != nil {
		return nil, fmt.Errorf("encode agent health agent: %w", err)
	}
	fields["tenant_id"], fields["agent_id"] = tenantID, agentID
	document, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encode agent health document: %w", err)
	}
	return document, nil
}
