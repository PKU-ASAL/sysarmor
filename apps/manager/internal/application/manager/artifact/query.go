package artifact

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type ArtifactQuery struct {
	Kind   string
	Status domainartifact.Status
}

func (service *Service) ListArtifacts(ctx context.Context, request managerapp.RequestContext, query ArtifactQuery) ([]domainartifact.Artifact, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	if err := service.requireComplete(); err != nil {
		return nil, err
	}
	var result []domainartifact.Artifact
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		var err error
		result, err = tx.Artifacts().List(txCtx, request.Actor.TenantID, ports.ArtifactFilter{
			Kind: strings.TrimSpace(query.Kind), Status: query.Status,
		})
		return err
	})
	return result, err
}

func (service *Service) GetArtifact(ctx context.Context, request managerapp.RequestContext, id string) (domainartifact.Artifact, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domainartifact.Artifact{}, err
	}
	if err := service.requireComplete(); err != nil {
		return domainartifact.Artifact{}, err
	}
	var result domainartifact.Artifact
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		var err error
		result, err = tx.Artifacts().Get(txCtx, request.Actor.TenantID, strings.TrimSpace(id))
		return err
	})
	return result, err
}

func (service *Service) ListChannels(ctx context.Context, request managerapp.RequestContext) ([]domainartifact.Channel, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	if err := service.requireComplete(); err != nil {
		return nil, err
	}
	var result []domainartifact.Channel
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		var err error
		result, err = tx.Channels().List(txCtx, request.Actor.TenantID)
		return err
	})
	return result, err
}

func (service *Service) GetChannel(ctx context.Context, request managerapp.RequestContext, name string) (domainartifact.Channel, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return domainartifact.Channel{}, err
	}
	if err := service.requireComplete(); err != nil {
		return domainartifact.Channel{}, err
	}
	var result domainartifact.Channel
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		var err error
		result, err = tx.Channels().Get(txCtx, request.Actor.TenantID, strings.TrimSpace(name))
		return err
	})
	return result, err
}
