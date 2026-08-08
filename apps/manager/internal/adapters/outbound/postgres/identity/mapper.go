package identity

import (
	"encoding/json"
	"fmt"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func decodeAgent(tenantID tenant.ID, id, host, version string, document []byte) (domainidentity.Agent, error) {
	var fields struct {
		AuthType            string `json:"auth_type"`
		CertificateIdentity string `json:"cert_identity"`
	}
	if err := json.Unmarshal(document, &fields); err != nil {
		return domainidentity.Agent{}, fmt.Errorf("decode agent: %w", err)
	}
	return domainidentity.Agent{TenantID: tenantID, ID: domainidentity.AgentID(id), HostID: host, Version: version, AuthType: fields.AuthType, CertificateIdentity: fields.CertificateIdentity}, nil
}

func decodeHealth(tenantID tenant.ID, agentID domainidentity.AgentID, host, scopeType, scopeSelector string, observed time.Time, document []byte) (domainidentity.Health, error) {
	var fields struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(document, &fields); err != nil {
		return domainidentity.Health{}, fmt.Errorf("decode agent health: %w", err)
	}
	canonical := map[string]json.RawMessage{}
	if err := json.Unmarshal(document, &canonical); err != nil {
		return domainidentity.Health{}, fmt.Errorf("decode health document: %w", err)
	}
	canonical["tenant_id"], _ = json.Marshal(tenantID.String())
	canonical["agent_id"], _ = json.Marshal(string(agentID))
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return domainidentity.Health{}, fmt.Errorf("encode health document: %w", err)
	}
	return domainidentity.Health{TenantID: tenantID, AgentID: agentID, HostID: host, Status: fields.Status, Scope: domainidentity.Scope{Type: scopeType, Selector: scopeSelector}, ObservedAt: observed, Document: encoded}, nil
}

func decodeSession(tenantID tenant.ID, id, agentID string, document []byte) (domainidentity.Session, error) {
	var wire struct {
		StartedAt         time.Time `json:"started_at"`
		LastSeenAt        time.Time `json:"last_seen_at"`
		LastDataSeenAt    time.Time `json:"last_data_seen_at"`
		LastControlSeenAt time.Time `json:"last_control_seen_at"`
		ClosedAt          time.Time `json:"closed_at"`
		LastAckCursor     string    `json:"last_ack_cursor"`
		DataTransport     string    `json:"data_transport"`
		ControlTransport  string    `json:"control_transport"`
		Status            string    `json:"status"`
	}
	if err := json.Unmarshal(document, &wire); err != nil {
		return domainidentity.Session{}, fmt.Errorf("decode agent session: %w", err)
	}
	return domainidentity.Session{
		TenantID: tenantID, ID: id, AgentID: domainidentity.AgentID(agentID),
		StartedAt: wire.StartedAt, LastSeenAt: wire.LastSeenAt,
		LastDataSeenAt: wire.LastDataSeenAt, LastControlSeenAt: wire.LastControlSeenAt, ClosedAt: wire.ClosedAt,
		LastAckCursor: wire.LastAckCursor, DataTransport: wire.DataTransport, ControlTransport: wire.ControlTransport, Status: wire.Status,
	}, nil
}
