package telemetry

import (
	"context"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestQueryRequiresTenant(t *testing.T) {
	service := NewQueryService(&telemetryReaderStub{})
	_, err := service.Events(context.Background(), managerapp.RequestContext{}, EventQuery{})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestEventsUseAuthenticatedTenant(t *testing.T) {
	reader := &telemetryReaderStub{events: []domaintelemetry.Document{[]byte(`{"id":"event-a"}`)}}
	service := NewQueryService(reader)
	result, err := service.Events(context.Background(), telemetryViewerRequest(t), EventQuery{
		Labels: map[string]string{"env": "prod"}, Behavior: "process.exec", Limit: 25, Offset: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || reader.tenantID != tenant.ID("tenant-a") || reader.eventFilter.Behavior != "process.exec" {
		t.Fatalf("result=%q tenant=%q filter=%+v", result, reader.tenantID, reader.eventFilter)
	}
}

type telemetryReaderStub struct {
	tenantID    tenant.ID
	eventFilter ports.EventFilter
	events      []domaintelemetry.Document
}

func (stub *telemetryReaderStub) Events(_ context.Context, tenantID tenant.ID, filter ports.EventFilter) ([]domaintelemetry.Document, error) {
	stub.tenantID, stub.eventFilter = tenantID, filter
	return stub.events, nil
}

func (stub *telemetryReaderStub) Signals(context.Context, tenant.ID, ports.SignalFilter) ([]domaintelemetry.Document, error) {
	return nil, nil
}

func (stub *telemetryReaderStub) Incidents(context.Context, tenant.ID, ports.IncidentFilter) ([]domaintelemetry.Document, error) {
	return nil, nil
}

func telemetryViewerRequest(t *testing.T) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
		Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
}
