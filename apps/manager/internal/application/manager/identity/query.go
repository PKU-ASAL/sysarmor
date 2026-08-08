package identity

import (
	"context"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type QueryService struct{ repositories ports.IdentityRepositories }

func NewQueryService(repositories ports.IdentityRepositories) *QueryService {
	return &QueryService{repositories: repositories}
}

type ListAgentsQuery struct{ Filter domainidentity.AgentFilter }
type ListAgentsResult struct{ Agents []domainidentity.Agent }

type ListHealthQuery struct{ Filter domainidentity.HealthFilter }
type ListHealthResult struct{ Health []domainidentity.Health }
type ListSessionsQuery struct{ Filter domainidentity.SessionFilter }
type ListSessionsResult struct{ Sessions []domainidentity.Session }
type ResumeResult struct {
	TenantID, AgentID, SessionID, ResumeCursor string
}

func (service *QueryService) ListAgents(ctx context.Context, request managerapp.RequestContext, query ListAgentsQuery) (ListAgentsResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ListAgentsResult{}, err
	}
	agents, err := service.repositories.Agents().List(ctx, request.Actor.TenantID, query.Filter)
	if err != nil {
		return ListAgentsResult{}, err
	}
	return ListAgentsResult{Agents: agents}, nil
}

func (service *QueryService) ListHealth(ctx context.Context, request managerapp.RequestContext, query ListHealthQuery) (ListHealthResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ListHealthResult{}, err
	}
	values, err := service.repositories.Health().List(ctx, request.Actor.TenantID, query.Filter)
	if err != nil {
		return ListHealthResult{}, err
	}
	return ListHealthResult{Health: values}, nil
}

func (service *QueryService) AgentOverview(ctx context.Context, request managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domainidentity.AgentOverview{}, err
	}
	agents, err := service.repositories.Agents().List(ctx, request.Actor.TenantID, domainidentity.AgentFilter{})
	if err != nil {
		return domainidentity.AgentOverview{}, fmt.Errorf("list agents: %w", err)
	}
	health, err := service.repositories.Health().List(ctx, request.Actor.TenantID, domainidentity.HealthFilter{})
	if err != nil {
		return domainidentity.AgentOverview{}, fmt.Errorf("list agent health: %w", err)
	}
	byAgent := make(map[domainidentity.AgentID]domainidentity.Health, len(health))
	for _, value := range health {
		byAgent[value.AgentID] = value
	}
	result := domainidentity.AgentOverview{Total: len(agents)}
	for _, agent := range agents {
		classifyOverviewHealth(&result, byAgent[agent.ID].Status)
	}
	return result, nil
}

func classifyOverviewHealth(result *domainidentity.AgentOverview, status string) {
	switch status {
	case "ok", "healthy":
		result.Online++
	case "degraded":
		result.Degraded++
	default:
		result.Offline++
	}
}

func (service *QueryService) ListSessions(ctx context.Context, request managerapp.RequestContext, query ListSessionsQuery) (ListSessionsResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ListSessionsResult{}, err
	}
	values, err := service.repositories.Sessions().List(ctx, request.Actor.TenantID, query.Filter)
	if err != nil {
		return ListSessionsResult{}, err
	}
	return ListSessionsResult{Sessions: values}, nil
}

func (service *QueryService) Resume(ctx context.Context, request managerapp.RequestContext, agentID string) (ResumeResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ResumeResult{}, err
	}
	values, err := service.repositories.Sessions().List(ctx, request.Actor.TenantID, domainidentity.SessionFilter{AgentID: agentID})
	if err != nil {
		return ResumeResult{}, err
	}
	result := ResumeResult{TenantID: request.Actor.TenantID.String(), AgentID: agentID}
	if len(values) > 0 {
		result.SessionID = values[0].ID
		result.ResumeCursor = values[0].LastAckCursor
	}
	return result, nil
}

func (service *QueryService) Metrics(ctx context.Context, request managerapp.RequestContext) (domainidentity.Metrics, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domainidentity.Metrics{}, err
	}
	return service.repositories.Snapshots().Metrics(ctx, request.Actor.TenantID)
}

func (service *QueryService) Rarity(ctx context.Context, request managerapp.RequestContext) (domainidentity.RarityBaseline, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domainidentity.RarityBaseline{}, err
	}
	return service.repositories.Snapshots().Rarity(ctx, request.Actor.TenantID)
}
