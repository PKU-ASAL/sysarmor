package identity

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CommandService struct{ health ports.AgentHealthWriter }

func NewCommandService(health ports.AgentHealthWriter) *CommandService {
	return &CommandService{health: health}
}

func (service *CommandService) RecordHealth(ctx context.Context, request managerapp.RequestContext, health domainidentity.Health) error {
	if err := request.Actor.Require(tenant.RoleAdmin); err != nil {
		return err
	}
	if strings.TrimSpace(string(health.AgentID)) == "" {
		return failure.New(failure.InvalidArgument, "agent_id is required")
	}
	health.TenantID = request.Actor.TenantID
	return service.health.Upsert(ctx, health)
}
