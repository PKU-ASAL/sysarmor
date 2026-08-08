package managerapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

func TestStoreStatusAPI(t *testing.T) {
	st := &store.Store{}
	handler := NewServer(st).Handler()
	rec := get(t, handler, "/healthz")
	for _, want := range []string{`"ok":true`, `"store"`, `"backend":"memory"`, `"postgres_schema_version":3`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("healthz missing %s: %s", want, rec.Body.String())
		}
	}
	rec = get(t, handler, "/api/v1/store-status")
	for _, want := range []string{`"backend":"memory"`, `"state_version":1`, `"migration_version":1`, `"postgres_schema_version":3`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("store status missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestAgentHealthIngestAndQuery(t *testing.T) {
	st := &store.Store{}
	handler := newAdminTestServer(st).Handler()
	health := agenthealth.AgentHealth{
		AgentID:          "agent-a",
		HostID:           "host-a",
		TenantID:         "default",
		Scope:            agenthealth.RuntimeScope{Type: "container", Selector: "abc123"},
		Status:           "ok",
		UptimeSeconds:    12,
		ObservedAt:       time.Now().UTC(),
		Capability:       agenthealth.SensorCapability{Backend: "fake", Version: "dev", SupportsExec: true, SupportsHealth: true, KernelRelease: "test-kernel", BTFAvailable: true, BPFFSAvailable: true},
		Sensor:           agenthealth.SensorHealth{Backend: "fake", Running: true, PolicyLoaded: true, EventsSeen: 3},
		TelemetryBatcher: agenthealth.TelemetryBatcherHealth{QueuedBatches: 1, QueueCapacity: 8},
		TelemetrySender:  agenthealth.TelemetrySenderHealth{SentBatches: 2},
	}
	data, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(string(data)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/agent-health?agent_id=agent-a&tenant_id=default")
	for _, want := range []string{`"agent_id":"agent-a"`, `"scope":{"type":"container","selector":"abc123"}`, `"sensor_capability"`, `"kernel_release":"test-kernel"`, `"sensor_health"`, `"telemetry_batcher_health"`, `"telemetry_sender_health"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("health response missing %s: %s", want, rec.Body.String())
		}
	}
	rec = get(t, handler, "/api/v1/agent-health")
	if !strings.Contains(rec.Body.String(), `"agent_id":"agent-a"`) {
		t.Fatalf("health list missing agent-a: %s", rec.Body.String())
	}
	st.AddAgent(store.AgentIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "default", Version: "test"})
	st.AddAgent(store.AgentIdentity{AgentID: "agent-b", HostID: "host-b", TenantID: "other", Version: "test"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{
		AgentID:    "agent-b",
		HostID:     "host-b",
		TenantID:   "other",
		Scope:      agenthealth.RuntimeScope{Type: "host"},
		Status:     "degraded",
		ObservedAt: time.Now().UTC(),
		Sensor:     agenthealth.SensorHealth{Backend: "fake", Running: false},
	})
	rec = get(t, handler, "/api/v1/agents")
	for _, want := range []string{`"agent_id":"agent-a"`, `"health_status":"ok"`, `"scope":{"type":"container","selector":"abc123"}`, `"sensor_capability":{"backend":"fake","version":"dev","supports_exec":true,"supports_health":true,"kernel_release":"test-kernel","btf_available":true,"bpffs_available":true}`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("agents response missing %s: %s", want, rec.Body.String())
		}
	}
	rec = get(t, handler, "/api/v1/agents?tenant_id=default&scope_type=container&health_status=ok")
	if !strings.Contains(rec.Body.String(), `"agent_id":"agent-a"`) || strings.Contains(rec.Body.String(), `"agent_id":"agent-b"`) {
		t.Fatalf("filtered agents response = %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/agents?tenant_id=default&scope_type=container&scope_selector=abc123&health_status=ok")
	if !strings.Contains(rec.Body.String(), `"agent_id":"agent-a"`) || strings.Contains(rec.Body.String(), `"agent_id":"agent-b"`) {
		t.Fatalf("filtered selector agents response = %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/agents?tenant_id=default&scope_type=container&scope_selector=missing&health_status=ok")
	if rec.Body.String() != "[]\n" {
		t.Fatalf("filtered missing selector response = %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/agents?tenant_id=other&scope_type=host&health_status=degraded")
	if !strings.Contains(rec.Body.String(), `"agent_id":"agent-b"`) || strings.Contains(rec.Body.String(), `"agent_id":"agent-a"`) {
		t.Fatalf("filtered other agents response = %s", rec.Body.String())
	}
}

func TestPrincipalGuardsHealthWrites(t *testing.T) {
	st := &store.Store{}
	handler := NewServer(st).Handler()

	health := agenthealth.AgentHealth{AgentID: "agent-a", HostID: "host-a", TenantID: "default", Status: "ok"}
	healthData, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(string(healthData)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("health without principal status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(string(healthData)))
	req = withTestPrincipal(req, "health-admin", "default", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health with admin principal status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentHealthListIsScopedToPrincipalTenant(t *testing.T) {
	st := &store.Store{}
	st.UpsertAgentHealth(agenthealth.AgentHealth{AgentID: "agent-a", TenantID: "tenant-a", Status: "ok"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{AgentID: "agent-b", TenantID: "tenant-b", Status: "ok"})
	handler := (&authenticatedTestServer{
		Server: NewServer(st),
		principal: managerauth.Principal{
			Subject: "viewer-a", TenantID: "tenant-a", Roles: []string{"viewer"},
		},
	}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "agent-a") || strings.Contains(rec.Body.String(), "agent-b") {
		t.Fatalf("agent health response = %s", rec.Body.String())
	}
}
