package artifact

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type RegisterCommand struct{ Value domainartifact.Artifact }

type ChangeStatusCommand struct {
	ArtifactID string
	Status     domainartifact.Status
}

func (service *Service) Register(ctx context.Context, request managerapp.RequestContext, command RegisterCommand) (domainartifact.Artifact, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainartifact.Artifact{}, err
	}
	if err := service.requireComplete(); err != nil {
		return domainartifact.Artifact{}, err
	}
	command.Value.TenantID = request.Actor.TenantID
	command.Value.CreatedBy = request.Actor.Subject
	value, err := domainartifact.New(command.Value, service.clock.Now())
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	var result domainartifact.Artifact
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		result, err = tx.Artifacts().Put(txCtx, value)
		return err
	})
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	return result, nil
}

func (service *Service) ChangeStatus(ctx context.Context, request managerapp.RequestContext, command ChangeStatusCommand) (domainartifact.Artifact, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainartifact.Artifact{}, err
	}
	if err := service.requireComplete(); err != nil {
		return domainartifact.Artifact{}, err
	}
	var result domainartifact.Artifact
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		current, err := tx.Artifacts().Get(txCtx, request.Actor.TenantID, strings.TrimSpace(command.ArtifactID))
		if err != nil {
			return err
		}
		result, err = current.ChangeStatus(command.Status, service.clock.Now())
		if err != nil {
			return err
		}
		result, err = tx.Artifacts().Put(txCtx, result)
		return err
	})
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	return result, nil
}
