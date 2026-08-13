package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestHealthPostUsesCommandAndCanonicalTenant(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	commands := &fakeCommands{}
	handler := NewHandler(Options{Commands: commands, Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}}, nil
	}})
	body := `{"tenant_id":"tenant-b","agent_id":"agent-a","host_id":"host-a","status":"ok","scope":{"type":"host"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.Health(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "{\"ok\":true}\n" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if commands.health.TenantID != tenantID || commands.health.AgentID != "agent-a" || !strings.Contains(string(commands.health.Document), `"tenant_id":"tenant-a"`) {
		t.Fatalf("health=%+v document=%s", commands.health, commands.health.Document)
	}
}

func TestHealthPostRejectsMissingAgentID(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(Options{Commands: identityapp.NewCommandService(fakeHealthWriter{}), Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}}, nil
	}})
	rec := httptest.NewRecorder()
	handler.Health(rec, httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(`{"status":"ok"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHealthPostAuthorizesBeforeDecodingBody(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(Options{Commands: identityapp.NewCommandService(fakeHealthWriter{}), Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}})
	recorder := httptest.NewRecorder()
	handler.Health(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/agent-health", strings.NewReader(`{"broken"`)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthUsesResolvedTenantAndPreservesDocument(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	query := &fakeQueries{health: domainidentity.Health{TenantID: tenantID, AgentID: "agent-a", Document: []byte(`{"tenant_id":"tenant-a","agent_id":"agent-a","status":"ok"}`)}}
	handler := NewHandler(Options{Query: query, Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-health?tenant_id=tenant-b&agent_id=agent-a", nil)
	rec := httptest.NewRecorder()
	handler.Health(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tenant_id":"tenant-a"`) || query.observedTenant != tenantID {
		t.Fatalf("status=%d body=%s tenant=%q", rec.Code, rec.Body.String(), query.observedTenant)
	}
}

func TestResumePreservesSnakeCaseJSON(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	query := &fakeQueries{resume: identityapp.ResumeResult{TenantID: "tenant-a", AgentID: "agent-a", SessionID: "session-a", ResumeCursor: "batch-7"}}
	handler := NewHandler(Options{Query: query, Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/data-resume?agent_id=agent-a", nil)
	rec := httptest.NewRecorder()
	handler.Resume(rec, req)
	for _, want := range []string{`"tenant_id":"tenant-a"`, `"agent_id":"agent-a"`, `"session_id":"session-a"`, `"resume_cursor":"batch-7"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("resume missing %s: %s", want, rec.Body.String())
		}
	}
}

type fakeQueries struct {
	health         domainidentity.Health
	resume         identityapp.ResumeResult
	observedTenant tenant.ID
}

type fakeCommands struct{ health domainidentity.Health }

func (commands *fakeCommands) RecordHealth(_ context.Context, _ managerapp.RequestContext, health domainidentity.Health) error {
	commands.health = health.Clone()
	return nil
}

type fakeHealthWriter struct{}

func (fakeHealthWriter) Upsert(context.Context, domainidentity.Health) error { return nil }

func (fake *fakeQueries) GetHealth(_ context.Context, request managerapp.RequestContext, _ domainidentity.AgentID) (domainidentity.Health, error) {
	fake.observedTenant = request.Actor.TenantID
	return fake.health, nil
}
func (*fakeQueries) ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error) {
	return identityapp.ListAgentsResult{}, nil
}
func (*fakeQueries) ListHealth(context.Context, managerapp.RequestContext, identityapp.ListHealthQuery) (identityapp.ListHealthResult, error) {
	return identityapp.ListHealthResult{}, nil
}
func (*fakeQueries) ListSessions(context.Context, managerapp.RequestContext, identityapp.ListSessionsQuery) (identityapp.ListSessionsResult, error) {
	return identityapp.ListSessionsResult{}, nil
}
func (fake *fakeQueries) Resume(context.Context, managerapp.RequestContext, string) (identityapp.ResumeResult, error) {
	return fake.resume, nil
}
func (*fakeQueries) Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error) {
	return domainidentity.Metrics{}, nil
}
func (*fakeQueries) Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error) {
	return domainidentity.RarityBaseline{}, nil
}
func (*fakeQueries) AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	return domainidentity.AgentOverview{}, nil
}
