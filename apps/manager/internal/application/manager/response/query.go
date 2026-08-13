package response

import (
	"context"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Query struct {
	AgentID string
	Pending bool
}

func (service *Service) List(ctx context.Context, request managerapp.RequestContext, query Query) ([]domainresponse.Command, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	if service == nil || service.uow == nil {
		return nil, failure.New(failure.Internal, "response service is incomplete")
	}
	var values []domainresponse.Command
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ResponseTransaction) error {
		var err error
		values, err = tx.Responses().List(txCtx, request.Actor.TenantID, ports.ResponseFilter{
			AgentID: query.AgentID, Pending: query.Pending,
		})
		return err
	})
	return values, err
}
