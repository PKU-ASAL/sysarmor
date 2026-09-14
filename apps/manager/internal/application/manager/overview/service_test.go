package overview

import (
	"context"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestQueryRequiresTenant(t *testing.T) {
	service := NewService(&identityStub{}, &telemetryStub{}, StorageStatus{})
	_, err := service.Query(context.Background(), managerapp.RequestContext{})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestQueryAggregatesIdentityTelemetryAndStorage(t *testing.T) {
	identity := &identityStub{agents: domainidentity.AgentOverview{Total: 3, Online: 2, Offline: 1},
		metrics: domainidentity.Metrics{EventsIngested: 12, SignalsEmitted: 5}}
	telemetry := &telemetryStub{overview: domaintelemetry.IncidentOverview{Open: 3, Critical: 1, High: 1, Medium: 1}}
	status := StorageStatus{Backend: "postgres", PostgresSchemaVersion: 6}
	service := NewService(identity, telemetry, status)

	result, err := service.Query(context.Background(), viewerRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if result.Agents.Total != 3 || result.Telemetry.Events24h != 12 || result.Incidents.Open != 3 ||
		result.Incidents.Critical != 1 || result.Incidents.High != 1 || result.Incidents.Medium != 1 ||
		result.Storage != status || identity.request.Actor.TenantID != "tenant-a" || telemetry.tenantID != "tenant-a" {
		t.Fatalf("result=%+v identity_request=%+v telemetry_tenant=%q", result, identity.request, telemetry.tenantID)
	}
}

func TestQueryPreservesTelemetryFailure(t *testing.T) {
	service := NewService(&identityStub{}, &telemetryStub{err: failure.New(failure.RetryableDependency, "unavailable")}, StorageStatus{})
	_, err := service.Query(context.Background(), viewerRequest(t))
	if failure.KindOf(err) != failure.RetryableDependency {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

type identityStub struct {
	request managerapp.RequestContext
	agents  domainidentity.AgentOverview
	metrics domainidentity.Metrics
}

func (stub *identityStub) AgentOverview(_ context.Context, request managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	stub.request = request
	return stub.agents, nil
}

func (stub *identityStub) Metrics(_ context.Context, request managerapp.RequestContext) (domainidentity.Metrics, error) {
	stub.request = request
	return stub.metrics, nil
}

type telemetryStub struct {
	tenantID tenant.ID
	overview domaintelemetry.IncidentOverview
	err      error
}

func (stub *telemetryStub) IncidentOverview(_ context.Context, tenantID tenant.ID) (domaintelemetry.IncidentOverview, error) {
	stub.tenantID = tenantID
	return stub.overview, stub.err
}

func viewerRequest(t *testing.T) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
		Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
}
