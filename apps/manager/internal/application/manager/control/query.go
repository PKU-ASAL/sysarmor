package control

import (
	"context"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CommandQuery struct {
	AgentID string
	Type    domaincontrol.CommandType
}

type EvidenceQuery struct{ AgentID string }

type QueryService struct{ uow ports.ControlUnitOfWork }

func NewQueryService(uow ports.ControlUnitOfWork) *QueryService { return &QueryService{uow: uow} }

func (service *QueryService) Commands(ctx context.Context, request managerapp.RequestContext, query CommandQuery) ([]domaincontrol.Command, error) {
	if err := service.authorize(request); err != nil {
		return nil, err
	}
	var values []domaincontrol.Command
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		var err error
		values, err = tx.Commands().List(txCtx, request.Actor.TenantID, ports.ControlFilter{
			AgentID: query.AgentID, Type: query.Type,
		})
		return err
	})
	return values, err
}

func (service *QueryService) Evidence(ctx context.Context, request managerapp.RequestContext, query EvidenceQuery) ([]domaincontrol.EvidencePullback, error) {
	if err := service.authorize(request); err != nil {
		return nil, err
	}
	var values []domaincontrol.EvidencePullback
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		var err error
		values, err = tx.Evidence().List(txCtx, request.Actor.TenantID, ports.EvidenceFilter{AgentID: query.AgentID})
		return err
	})
	return values, err
}

func (service *QueryService) authorize(request managerapp.RequestContext) error {
	if service == nil || service.uow == nil {
		return failure.New(failure.Internal, "control query service is incomplete")
	}
	return request.Actor.Require(tenant.RoleViewer)
}
