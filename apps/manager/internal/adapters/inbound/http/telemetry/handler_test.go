package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestEventsUseAuthenticatedTenantAndPreserveRawList(t *testing.T) {
	service := &telemetryServiceStub{events: []domaintelemetry.Document{[]byte(`{"id":"event-a"}`)}}
	handler := NewHandler(Options{Service: service, Resolve: telemetryResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Events(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/events?tenant_id=tenant-b&behavior=process.exec&label=env=prod", nil))

	if recorder.Code != http.StatusOK || recorder.Body.String() != "[{\"id\":\"event-a\"}]\n" {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.request.Actor.TenantID != "tenant-a" || service.eventQuery.Labels["env"] != "prod" {
		t.Fatalf("request=%+v query=%+v", service.request, service.eventQuery)
	}
}

func TestIncidentByIDReturnsNotFoundWhenMissing(t *testing.T) {
	service := &telemetryServiceStub{}
	handler := NewHandler(Options{Service: service, Resolve: telemetryResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Incidents(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/incidents?incident_id=missing&tenant_id=tenant-b", nil))

	if recorder.Code != http.StatusNotFound || service.incidentQuery.ID != "missing" ||
		service.request.Actor.TenantID != "tenant-a" {
		t.Fatalf("status=%d request=%+v query=%+v body=%s", recorder.Code, service.request, service.incidentQuery, recorder.Body.String())
	}
}

type telemetryServiceStub struct {
	request       managerapp.RequestContext
	eventQuery    telemetryapp.EventQuery
	incidentQuery telemetryapp.IncidentQuery
	events        []domaintelemetry.Document
}

func (stub *telemetryServiceStub) Events(_ context.Context, request managerapp.RequestContext, query telemetryapp.EventQuery) ([]domaintelemetry.Document, error) {
	stub.request, stub.eventQuery = request, query
	return stub.events, nil
}

func (stub *telemetryServiceStub) Signals(context.Context, managerapp.RequestContext, telemetryapp.SignalQuery) ([]domaintelemetry.Document, error) {
	return nil, nil
}

func (stub *telemetryServiceStub) Incidents(_ context.Context, request managerapp.RequestContext, query telemetryapp.IncidentQuery) ([]domaintelemetry.Document, error) {
	stub.request, stub.incidentQuery = request, query
	return nil, nil
}

func telemetryResolver(t *testing.T) RequestContextResolver {
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
