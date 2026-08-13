package policy

import (
	"context"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type SavePolicyCommand struct {
	Policy domainpolicy.Policy
	Reason string
}

type SavePolicyResult struct{ Policy domainpolicy.Policy }

type SaveService struct {
	uow   ports.PolicyUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewSaveService(uow ports.PolicyUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *SaveService {
	return &SaveService{uow: uow, clock: clock, ids: ids}
}

func (service *SaveService) Execute(ctx context.Context, request managerapp.RequestContext, command SavePolicyCommand) (SavePolicyResult, error) {
	var result SavePolicyResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		current, err := tx.Policies().Current(txCtx, request.Actor.TenantID, command.Policy.ID)
		if err != nil && failure.KindOf(err) != failure.NotFound {
			return fmt.Errorf("get current policy: %w", err)
		}
		saved, record, err := domainpolicy.Save(current, command.Policy, request.Actor, service.clock.Now())
		if err != nil {
			return err
		}
		record.ID, record.Reason = service.ids.New(), command.Reason
		if err := tx.Policies().Put(txCtx, saved); err != nil {
			return fmt.Errorf("put policy: %w", err)
		}
		if err := tx.Audits().Append(txCtx, saved.TenantID, record); err != nil {
			return fmt.Errorf("append policy audit: %w", err)
		}
		result.Policy = saved
		return nil
	})
	return result, err
}
