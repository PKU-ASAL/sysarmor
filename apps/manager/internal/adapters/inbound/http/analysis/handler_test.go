package analysis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	analysisapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/analysis"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestRecomputeUsesAuthenticatedTenantAndPreservesJSON(t *testing.T) {
	service := &serviceStub{result: domaintelemetry.Analysis{
		CloudSignals: []domaintelemetry.Signal{{ID: "cloud-a", Name: "web_shell_chain", Where: domaintelemetry.SignalWhereCloud}},
		Incidents:    []domaintelemetry.Incident{{ID: "inc-a"}},
	}}
	handler := NewHandler(Options{Service: service, Resolve: analysisResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Recompute(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/recompute?tenant_id=tenant-b&agent_id=agent-a&scope_type=host&scope_selector=prod&label=scenario=one", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"cloud_signals\":[{\"id\":\"cloud-a\",\"name\":\"web_shell_chain\",\"where\":\"SIGNAL_WHERE_CLOUD\"}],\"incidents\":[{\"id\":\"inc-a\"}]}\n" {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if service.request.Actor.TenantID != "tenant-a" || service.query.Target.AgentID != "agent-a" || service.query.Labels["scenario"] != "one" {
		t.Fatalf("request = %+v, query = %+v", service.request, service.query)
	}
}

func TestRecomputeMapsRetryableDependency(t *testing.T) {
	handler := NewHandler(Options{Service: &serviceStub{err: failure.New(failure.RetryableDependency, "search unavailable")}, Resolve: analysisResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Recompute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/recompute", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

type serviceStub struct {
	request managerapp.RequestContext
	query   analysisapp.Query
	result  domaintelemetry.Analysis
	err     error
}

func (stub *serviceStub) Recompute(_ context.Context, request managerapp.RequestContext, query analysisapp.Query) (domaintelemetry.Analysis, error) {
	stub.request, stub.query = request, query
	return stub.result, stub.err
}

func analysisResolver(t *testing.T) RequestContextResolver {
	t.Helper()
	tenantID, _ := tenant.NewID("tenant-a")
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
			Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}
}
