package identity

import (
	"context"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestListAgentsUsesActorTenant(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	repositories := &fakeIdentityRepositories{agents: []domainidentity.Agent{{TenantID: tenantID, ID: "agent-a"}}}
	service := NewQueryService(repositories)
	request := managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}

	result, err := service.ListAgents(context.Background(), request, ListAgentsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if repositories.observedTenant != tenantID || len(result.Agents) != 1 {
		t.Fatalf("result=%+v tenant=%q", result, repositories.observedTenant)
	}
}

func TestListHealthUsesActorTenant(t *testing.T) {
	tenantID, request := identityRequest(t, "tenant-a")
	repositories := &fakeIdentityRepositories{health: []domainidentity.Health{{TenantID: tenantID, AgentID: "agent-a"}}}
	result, err := NewQueryService(repositories).ListHealth(context.Background(), request, ListHealthQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if repositories.observedTenant != tenantID || len(result.Health) != 1 {
		t.Fatalf("result=%+v tenant=%q", result, repositories.observedTenant)
	}
}

func TestListAgentsFiltersJoinedHealthInApplication(t *testing.T) {
	tenantID, request := identityRequest(t, "tenant-a")
	repositories := &fakeIdentityRepositories{
		agents: []domainidentity.Agent{{TenantID: tenantID, ID: "agent-a"}, {TenantID: tenantID, ID: "agent-b"}},
		health: []domainidentity.Health{{TenantID: tenantID, AgentID: "agent-a", Status: "ok", Scope: domainidentity.Scope{Type: "host"}}},
	}
	result, err := NewQueryService(repositories).ListAgents(context.Background(), request, ListAgentsQuery{Filter: domainidentity.AgentFilter{ScopeType: "host", HealthStatus: "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Agents) != 1 || result.Agents[0].Agent.ID != "agent-a" {
		t.Fatalf("agents = %+v", result.Agents)
	}
}

func TestAgentOverviewCountsMissingHealthAsOffline(t *testing.T) {
	tenantID, request := identityRequest(t, "tenant-a")
	repositories := &fakeIdentityRepositories{agents: []domainidentity.Agent{{TenantID: tenantID, ID: "agent-a"}, {TenantID: tenantID, ID: "agent-b"}}, health: []domainidentity.Health{{TenantID: tenantID, AgentID: "agent-a", Status: "ok"}}}
	result, err := NewQueryService(repositories).AgentOverview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || result.Online != 1 || result.Offline != 1 {
		t.Fatalf("overview=%+v", result)
	}
}

func TestResumeUsesLatestTenantSession(t *testing.T) {
	tenantID, request := identityRequest(t, "tenant-a")
	repositories := &fakeIdentityRepositories{sessions: []domainidentity.Session{{TenantID: tenantID, ID: "session-a", AgentID: "agent-a", LastAckCursor: "batch-7"}}}
	result, err := NewQueryService(repositories).Resume(context.Background(), request, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "session-a" || result.ResumeCursor != "batch-7" || repositories.observedTenant != tenantID {
		t.Fatalf("resume=%+v tenant=%q", result, repositories.observedTenant)
	}
}

func identityRequest(t *testing.T, raw string) (tenant.ID, managerapp.RequestContext) {
	t.Helper()
	tenantID, err := tenant.NewID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tenantID, managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
}

type fakeIdentityRepositories struct {
	agents         []domainidentity.Agent
	health         []domainidentity.Health
	sessions       []domainidentity.Session
	observedTenant tenant.ID
}

func (fake *fakeIdentityRepositories) Agents() ports.AgentRepository {
	return fakeAgentRepository{fake: fake}
}
func (fake *fakeIdentityRepositories) Health() ports.AgentHealthRepository {
	return fakeHealthRepository{fake: fake}
}
func (fake *fakeIdentityRepositories) Sessions() ports.AgentSessionRepository {
	return fakeSessionRepository{fake: fake}
}
func (fake *fakeIdentityRepositories) Snapshots() ports.IdentitySnapshotRepository {
	return fakeSnapshotRepository{}
}

type fakeAgentRepository struct{ fake *fakeIdentityRepositories }

func (repo fakeAgentRepository) List(_ context.Context, tenantID tenant.ID, _ domainidentity.AgentFilter) ([]domainidentity.Agent, error) {
	repo.fake.observedTenant = tenantID
	return repo.fake.agents, nil
}

type fakeHealthRepository struct{ fake *fakeIdentityRepositories }

func (fakeHealthRepository) Get(context.Context, tenant.ID, domainidentity.AgentID) (domainidentity.Health, error) {
	return domainidentity.Health{}, nil
}
func (repo fakeHealthRepository) List(_ context.Context, tenantID tenant.ID, _ domainidentity.HealthFilter) ([]domainidentity.Health, error) {
	repo.fake.observedTenant = tenantID
	return repo.fake.health, nil
}

type fakeSessionRepository struct{ fake *fakeIdentityRepositories }

func (repo fakeSessionRepository) List(_ context.Context, tenantID tenant.ID, _ domainidentity.SessionFilter) ([]domainidentity.Session, error) {
	repo.fake.observedTenant = tenantID
	return repo.fake.sessions, nil
}

type fakeSnapshotRepository struct{}

func (fakeSnapshotRepository) Metrics(context.Context, tenant.ID) (domainidentity.Metrics, error) {
	return domainidentity.Metrics{}, nil
}
func (fakeSnapshotRepository) Rarity(context.Context, tenant.ID) (domainidentity.RarityBaseline, error) {
	return domainidentity.RarityBaseline{}, nil
}
