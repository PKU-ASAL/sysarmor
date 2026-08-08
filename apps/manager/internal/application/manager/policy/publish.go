package policy

import (
	"context"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type PublishPolicyCommand struct {
	PolicyID  domainpolicy.ID
	Version   domainpolicy.Version
	Published bool
	Reason    string
}

type PublishPolicyResult struct {
	Policy domainpolicy.Policy
}

type PublishService struct {
	uow   ports.PolicyUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewPublishService(uow ports.PolicyUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *PublishService {
	return &PublishService{uow: uow, clock: clock, ids: ids}
}

func (service *PublishService) Execute(ctx context.Context, request managerapp.RequestContext, command PublishPolicyCommand) (PublishPolicyResult, error) {
	var result PublishPolicyResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		candidate, err := tx.Policies().Get(txCtx, request.Actor.TenantID, command.PolicyID, command.Version)
		if err != nil {
			return fmt.Errorf("get policy candidate: %w", err)
		}
		current, err := tx.Policies().Current(txCtx, request.Actor.TenantID, command.PolicyID)
		if err != nil {
			return fmt.Errorf("get current policy: %w", err)
		}
		candidate.Published = command.Published
		published, record, err := domainpolicy.Publish(current, candidate, request.Actor, service.clock.Now())
		if err != nil {
			return err
		}
		record.ID, record.Reason = service.ids.New(), command.Reason
		if err := tx.Policies().Put(txCtx, published); err != nil {
			return fmt.Errorf("put policy: %w", err)
		}
		if err := tx.Audits().Append(txCtx, published.TenantID, record); err != nil {
			return fmt.Errorf("append policy audit: %w", err)
		}
		result.Policy = published
		return nil
	})
	return result, err
}
