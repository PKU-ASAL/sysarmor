package overview

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	overviewapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/overview"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestHandlerReturnsOverviewJSON(t *testing.T) {
	service := &serviceStub{result: overviewapp.Result{
		Agents:    domainidentity.AgentOverview{Total: 3, Online: 2, Offline: 1},
		Telemetry: overviewapp.TelemetrySummary{Events24h: 12, Signals24h: 5},
		Incidents: domaintelemetry.IncidentOverview{Open: 2, Critical: 1, High: 1},
		Storage:   overviewapp.StorageStatus{Backend: "postgres", PostgresSchemaVersion: 9},
	}}
	handler := NewHandler(Options{Service: service, Resolve: requestResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Overview(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview?tenant_id=other", nil))

	if recorder.Code != http.StatusOK || service.request.Actor.TenantID != "tenant-a" {
		t.Fatalf("status=%d request=%+v body=%s", recorder.Code, service.request, recorder.Body.String())
	}
	for _, want := range []string{`"generated_at":`, `"total":3`, `"events_24h":12`, `"signals_24h":5`,
		`"open":2`, `"critical":1`, `"backend":"postgres"`, `"postgres_schema_version":9`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("overview response missing %s: %s", want, recorder.Body.String())
		}
	}
}

func TestHandlerMapsRetryableDependencyToBadGateway(t *testing.T) {
	handler := NewHandler(Options{Service: &serviceStub{err: failure.New(failure.RetryableDependency, "search unavailable")},
		Resolve: requestResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Overview(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type serviceStub struct {
	request managerapp.RequestContext
	result  overviewapp.Result
	err     error
}

func (stub *serviceStub) Query(_ context.Context, request managerapp.RequestContext) (overviewapp.Result, error) {
	stub.request = request
	return stub.result, stub.err
}

func requestResolver(t *testing.T) RequestContextResolver {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
			Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}
}
