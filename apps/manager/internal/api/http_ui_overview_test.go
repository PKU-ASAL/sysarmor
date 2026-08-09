package managerapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
)

func TestUIOverviewUsesIdentityApplicationSummaries(t *testing.T) {
	server := NewServer(&store.Store{})
	server.SetIdentityApplication(&testIdentityQueries{
		overview: domainidentity.AgentOverview{Total: 3, Online: 2, Offline: 1},
		metrics:  domainidentity.Metrics{EventsIngested: 12, SignalsEmitted: 5},
	}, PolicyRequestContext)
	rec := get(t, server.Handler(), "/api/v1/ui/overview")
	var got overviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Agents.Total != 3 || got.Agents.Online != 2 || got.Telemetry.Events24h != 12 || got.Telemetry.Signals24h != 5 {
		t.Fatalf("overview = %+v", got)
	}
}

func TestUIOverviewReturnsManagerSummary(t *testing.T) {
	st := &store.Store{}
	st.AddAgent(store.AgentIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "default"})
	st.AddAgent(store.AgentIdentity{AgentID: "agent-b", HostID: "host-b", TenantID: "default"})
	st.AddAgent(store.AgentIdentity{AgentID: "agent-c", HostID: "host-c", TenantID: "default"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{
		AgentID:    "agent-a",
		TenantID:   "default",
		Status:     "ok",
		ObservedAt: time.Now().UTC(),
	})
	st.UpsertAgentHealth(agenthealth.AgentHealth{
		AgentID:    "agent-b",
		TenantID:   "default",
		Status:     "degraded",
		ObservedAt: time.Now().UTC(),
	})
	seedTenantTelemetry(t, st, "default", "overview-default", store.Metrics{DataBatchesAppended: 1, EventsIngested: 12, SignalsEmitted: 5}, nil)
	st.Incidents = []*incidentv1.Incident{
		{Id: "inc-critical", TenantId: "default", Severity: 95},
		{Id: "inc-high", TenantId: "default", Severity: 75},
		{Id: "inc-medium", TenantId: "default", Severity: 45},
	}

	rec := get(t, newTestServer(st).Handler(), "/api/v1/ui/overview")
	var got struct {
		Agents struct {
			Total    int `json:"total"`
			Online   int `json:"online"`
			Degraded int `json:"degraded"`
			Offline  int `json:"offline"`
		} `json:"agents"`
		Telemetry struct {
			Events24h  uint64 `json:"events_24h"`
			Signals24h uint64 `json:"signals_24h"`
		} `json:"telemetry"`
		Incidents struct {
			Open     int `json:"open"`
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
		} `json:"incidents"`
		Store struct {
			Backend string `json:"backend"`
		} `json:"store"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode overview: %v body=%s", err, rec.Body.String())
	}
	if got.Agents.Total != 3 || got.Agents.Online != 1 || got.Agents.Degraded != 1 || got.Agents.Offline != 1 {
		t.Fatalf("agents summary = %+v", got.Agents)
	}
	if got.Telemetry.Events24h != 12 || got.Telemetry.Signals24h != 5 {
		t.Fatalf("telemetry summary = %+v", got.Telemetry)
	}
	if got.Incidents.Open != 3 || got.Incidents.Critical != 1 || got.Incidents.High != 1 || got.Incidents.Medium != 1 {
		t.Fatalf("incident summary = %+v", got.Incidents)
	}
	if got.Store.Backend != "memory" {
		t.Fatalf("store backend = %q", got.Store.Backend)
	}
}

func TestUIOverviewIsScopedToPrincipalTenant(t *testing.T) {
	st := &store.Store{}
	st.AddAgent(store.AgentIdentity{AgentID: "agent-a", TenantID: "tenant-a"})
	st.AddAgent(store.AgentIdentity{AgentID: "agent-b", TenantID: "tenant-b"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{AgentID: "agent-a", TenantID: "tenant-a", Status: "ok"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{AgentID: "agent-b", TenantID: "tenant-b", Status: "degraded"})
	st.AddIncident(&incidentv1.Incident{Id: "incident-a", TenantId: "tenant-a", Summary: "incident a", Severity: 95})
	st.AddIncident(&incidentv1.Incident{Id: "incident-b", TenantId: "tenant-b", Summary: "incident b", Severity: 75})
	seedTenantTelemetry(t, st, "tenant-a", "overview-a", store.Metrics{DataBatchesAppended: 1, EventsIngested: 2, SignalsEmitted: 1, IncidentsCreated: 1}, nil)
	seedTenantTelemetry(t, st, "tenant-b", "overview-b", store.Metrics{DataBatchesAppended: 1, EventsIngested: 20, SignalsEmitted: 10, IncidentsCreated: 1}, nil)
	handler := tenantTestHandler(newTestServer(st), "tenant-a")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var got overviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode overview: %v body=%s", err, rec.Body.String())
	}
	if got.Agents.Total != 1 || got.Agents.Online != 1 || got.Agents.Degraded != 0 {
		t.Fatalf("agents summary = %+v", got.Agents)
	}
	if got.Telemetry.Events24h != 2 || got.Telemetry.Signals24h != 1 {
		t.Fatalf("telemetry summary = %+v", got.Telemetry)
	}
	if got.Incidents.Open != 1 || got.Incidents.Critical != 1 || got.Incidents.High != 0 {
		t.Fatalf("incident summary = %+v", got.Incidents)
	}
}

func TestUIOverviewRejectsSearchDocumentsFromAnotherTenant(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.IncidentsReadAlias: {
			json.RawMessage(`{"id":"incident-a","tenant_id":"tenant-a","severity":95}`),
			json.RawMessage(`{"id":"incident-b","tenant_id":"tenant-b","severity":75}`),
			json.RawMessage(`{"id":"incident-missing","severity":45}`),
		},
	}}
	server := NewServerWithSearch(&store.Store{}, searcher)
	server.SetIdentityApplication(testIdentityQuery(&store.Store{}), PolicyRequestContext)
	server.localTelemetry = false
	handler := tenantTestHandler(server, "tenant-a")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var got overviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode overview: %v body=%s", err, rec.Body.String())
	}
	if got.Incidents.Open != 1 || got.Incidents.Critical != 1 || got.Incidents.High != 0 || got.Incidents.Medium != 0 {
		t.Fatalf("incident summary = %+v, want only tenant-a", got.Incidents)
	}
}
