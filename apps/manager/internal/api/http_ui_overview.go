package managerapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type overviewResponse struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Agents      overviewAgentsSummary `json:"agents"`
	Telemetry   overviewTelemetry     `json:"telemetry"`
	Incidents   overviewIncidents     `json:"incidents"`
	Store       overviewStore         `json:"store"`
}

type overviewAgentsSummary struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Degraded int `json:"degraded"`
	Offline  int `json:"offline"`
}

type overviewTelemetry struct {
	Events24h  uint64 `json:"events_24h"`
	Signals24h uint64 `json:"signals_24h"`
}

type overviewIncidents struct {
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

type overviewStore struct {
	Backend               string `json:"backend"`
	PostgresSchemaVersion int    `json:"postgres_schema_version,omitempty"`
}

func (s *Server) uiOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := requestTenantID(r)
	if tenantID == "" && !s.localTelemetry {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}
	incidents, err := s.overviewIncidents(r.Context(), tenantID)
	if err != nil {
		http.Error(w, fmt.Sprintf("query incident reports: %v", err), http.StatusBadGateway)
		return
	}
	info := s.store.Info()
	agents, metrics, err := s.overviewIdentity(r, tenantID)
	if err != nil {
		http.Error(w, fmt.Sprintf("read agent overview: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, overviewResponse{
		GeneratedAt: time.Now().UTC(),
		Agents:      agents,
		Telemetry: overviewTelemetry{
			Events24h:  metrics.EventsIngested,
			Signals24h: metrics.SignalsEmitted,
		},
		Incidents: incidents,
		Store: overviewStore{
			Backend:               info.Backend,
			PostgresSchemaVersion: info.PostgresSchema,
		},
	})
}

func (s *Server) overviewIdentity(r *http.Request, tenantID string) (overviewAgentsSummary, domainidentity.Metrics, error) {
	if s.identityRoutes != nil {
		agents, err := s.identityRoutes.AgentOverview(r)
		if err != nil {
			return overviewAgentsSummary{}, domainidentity.Metrics{}, err
		}
		metrics, err := s.identityRoutes.MetricsQuery(r)
		return overviewAgentsSummary{Total: agents.Total, Online: agents.Online, Degraded: agents.Degraded, Offline: agents.Offline}, metrics, err
	}
	agents, err := s.overviewAgents(tenantID)
	if err != nil {
		return overviewAgentsSummary{}, domainidentity.Metrics{}, err
	}
	metrics, err := s.store.MetricsSnapshotForTenantWithError(tenantID)
	return agents, domainidentity.Metrics{EventsIngested: metrics.EventsIngested, SignalsEmitted: metrics.SignalsEmitted}, err
}

func (s *Server) overviewAgents(tenantID string) (overviewAgentsSummary, error) {
	agents, err := s.store.ListAgentsWithError()
	if err != nil {
		return overviewAgentsSummary{}, err
	}
	summary := overviewAgentsSummary{}

	for _, agent := range agents {
		if agent.TenantID != tenantID {
			continue
		}
		summary.Total++
		health, ok, err := s.store.GetAgentHealthWithError(agent.TenantID, agent.AgentID)
		if err != nil {
			return overviewAgentsSummary{}, err
		}
		if !ok {
			summary.Offline++
			continue
		}
		switch health.Status {
		case "ok", "healthy":
			summary.Online++
		case "degraded":
			summary.Degraded++
		default:
			summary.Offline++
		}
	}

	return summary, nil
}

func (s *Server) overviewIncidents(ctx context.Context, tenantID string) (overviewIncidents, error) {
	summary := overviewIncidents{}
	if s.localTelemetry {
		for _, incident := range s.store.ListIncidents(nil) {
			if incident.GetTenantId() != tenantID {
				continue
			}
			addOverviewIncident(&summary, incident)
		}
		return summary, nil
	}
	if s.searcher == nil {
		return summary, nil
	}
	raw, err := s.searchTelemetry(ctx, platformopensearch.SearchRequest{Index: platformopensearch.IncidentsReadAlias, Size: 1000, Exact: map[string]string{"tenant_id": tenantID}})
	if err != nil {
		return summary, err
	}
	raw = filterRawTelemetry(raw, nil, rawStringEquals("tenant_id", tenantID))
	for _, document := range raw {
		incident := &incidentv1.Incident{}
		if err := protojson.Unmarshal(document, incident); err != nil {
			return summary, err
		}
		addOverviewIncident(&summary, incident)
	}
	return summary, nil
}

func addOverviewIncident(summary *overviewIncidents, incident *incidentv1.Incident) {
	summary.Open++
	switch {
	case incident.GetSeverity() >= 90:
		summary.Critical++
	case incident.GetSeverity() >= 70:
		summary.High++
	case incident.GetSeverity() >= 40:
		summary.Medium++
	}
}
