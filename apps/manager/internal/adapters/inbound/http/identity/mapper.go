package identity

import (
	"encoding/json"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

func healthDocuments(values []domainidentity.Health) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		result = append(result, append(json.RawMessage(nil), value.Document...))
	}
	return result
}

func agentItems(values []domainidentity.AgentView) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, view := range values {
		agent, value := view.Agent, view.Health
		item := map[string]any{"agent_id": string(agent.ID), "host_id": agent.HostID, "tenant_id": agent.TenantID.String()}
		setOptional(item, "version", agent.Version)
		setOptional(item, "auth_type", agent.AuthType)
		setOptional(item, "cert_identity", agent.CertificateIdentity)
		setOptional(item, "health_status", value.Status)
		if value.Scope.Type != "" || value.Scope.Selector != "" {
			item["scope"] = map[string]string{"type": value.Scope.Type, "selector": value.Scope.Selector}
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(value.Document, &fields) == nil && len(fields["sensor_capability"]) > 0 {
			item["sensor_capability"] = fields["sensor_capability"]
		}
		if !value.ObservedAt.IsZero() {
			item["health_observed_at"] = value.ObservedAt
		}
		result = append(result, item)
	}
	return result
}

func setOptional(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}

func sessionDTOs(values []domainidentity.Session) []sessionDTO {
	result := make([]sessionDTO, 0, len(values))
	for _, value := range values {
		result = append(result, sessionDTO{SessionID: value.ID, TenantID: value.TenantID.String(), AgentID: string(value.AgentID), StartedAt: value.StartedAt, LastSeenAt: value.LastSeenAt, LastDataSeenAt: value.LastDataSeenAt, LastControlSeenAt: value.LastControlSeenAt, ClosedAt: value.ClosedAt, LastAckCursor: value.LastAckCursor, DataTransport: value.DataTransport, ControlTransport: value.ControlTransport, Status: value.Status})
	}
	return result
}

func mapMetrics(value domainidentity.Metrics) metricsDTO {
	return metricsDTO{DataBatchesAppended: value.DataBatchesAppended, EventsIngested: value.EventsIngested, EndpointSignalsIngested: value.EndpointSignalsIngested, CloudSignalsEmitted: value.CloudSignalsEmitted, SignalsEmitted: value.SignalsEmitted, IncidentsCreated: value.IncidentsCreated, DroppedEvents: value.DroppedEvents, DuplicateEvents: value.DuplicateEvents, LastConvergenceLatencyMs: value.LastConvergenceLatencyMs, MaxConvergenceLatencyMs: value.MaxConvergenceLatencyMs, TotalConvergenceLatencyMs: value.TotalConvergenceLatencyMs, AverageConvergenceLatency: value.AverageConvergenceLatency}
}

func rarityDocument(value domainidentity.RarityBaseline) any {
	if len(value.Document) > 0 {
		return json.RawMessage(value.Document)
	}
	return map[string]any{"WorkloadCounts": value.WorkloadCounts}
}
