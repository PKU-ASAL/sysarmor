package artifact

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Service struct {
	uow     ports.ArtifactUnitOfWork
	archive ports.ArtifactArchive
	clock   ports.Clock
}

func NewService(uow ports.ArtifactUnitOfWork, clock ports.Clock) *Service {
	return &Service{uow: uow, clock: clock}
}

func NewServiceWithArchive(uow ports.ArtifactUnitOfWork, archive ports.ArtifactArchive, clock ports.Clock) *Service {
	return &Service{uow: uow, archive: archive, clock: clock}
}

func (service *Service) requireComplete() error {
	if service == nil || service.uow == nil || service.clock == nil {
		return failure.New(failure.Internal, "artifact service is incomplete")
	}
	return nil
}

func (service *Service) requireArchive() error {
	if err := service.requireComplete(); err != nil {
		return err
	}
	if service.archive == nil {
		return failure.New(failure.Internal, "artifact archive is incomplete")
	}
	return nil
}

type SetChannelCommand struct {
	Name       string
	ArtifactID string
}

func (service *Service) SetChannel(ctx context.Context, request managerapp.RequestContext, command SetChannelCommand) (domainartifact.Channel, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainartifact.Channel{}, err
	}
	if err := service.requireComplete(); err != nil {
		return domainartifact.Channel{}, err
	}
	var result domainartifact.Channel
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		artifact, err := tx.Artifacts().Get(txCtx, request.Actor.TenantID, strings.TrimSpace(command.ArtifactID))
		if err != nil {
			if failure.KindOf(err) == failure.NotFound {
				return failure.New(failure.FailedPrecondition, "active artifact not found")
			}
			return err
		}
		result, err = domainartifact.NewChannel(domainartifact.Channel{
			TenantID: request.Actor.TenantID, Name: command.Name,
		}, artifact, request.Actor.Subject, service.clock.Now())
		if err != nil {
			return err
		}
		result, err = tx.Channels().Put(txCtx, result)
		return err
	})
	if err != nil {
		return domainartifact.Channel{}, err
	}
	return result, nil
}
