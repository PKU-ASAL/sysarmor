package identity

import (
	"context"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestRecordHealthUsesAuthenticatedTenant(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeHealthWriter{}
	service := NewCommandService(writer)
	request := managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}}

	err = service.RecordHealth(context.Background(), request, domainidentity.Health{
		TenantID: "tenant-b", AgentID: "agent-a", Document: []byte(`{"tenant_id":"tenant-b","agent_id":"agent-a"}`),
	})

	if err != nil {
		t.Fatal(err)
	}
	if writer.health.TenantID != tenantID {
		t.Fatalf("written tenant = %q, want %q", writer.health.TenantID, tenantID)
	}
}

func TestRecordHealthRequiresAdminAndAgentIdentity(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	service := NewCommandService(&fakeHealthWriter{})
	viewer := managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
	if err := service.RecordHealth(context.Background(), viewer, domainidentity.Health{AgentID: "agent-a"}); failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("viewer error kind = %q", failure.KindOf(err))
	}
	admin := managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}}
	if err := service.RecordHealth(context.Background(), admin, domainidentity.Health{}); failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("blank agent error kind = %q", failure.KindOf(err))
	}
}

type fakeHealthWriter struct{ health domainidentity.Health }

func (writer *fakeHealthWriter) Upsert(_ context.Context, health domainidentity.Health) error {
	writer.health = health.Clone()
	return nil
}
