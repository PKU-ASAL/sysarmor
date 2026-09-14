package response

import (
	"context"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type AcknowledgeCommand struct {
	TenantID    string
	ResponseID  string
	AgentID     string
	Accepted    bool
	Unsupported bool
	ObserveOnly bool
	Executed    bool
	Message     string
	ObservedAt  time.Time
}

func (service *Service) Acknowledge(ctx context.Context, input AcknowledgeCommand) (domainresponse.Acknowledged, error) {
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return domainresponse.Acknowledged{}, failure.New(failure.Internal, "response service is incomplete")
	}
	tenantID, err := tenant.NewID(input.TenantID)
	if err != nil {
		return domainresponse.Acknowledged{}, err
	}
	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = service.clock.Now()
	}
	var result domainresponse.Acknowledged
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ResponseTransaction) error {
		current, err := tx.Responses().Get(txCtx, tenantID, strings.TrimSpace(input.ResponseID))
		if err != nil {
			return err
		}
		result, err = current.Acknowledge(domainresponse.Acknowledgement{
			TenantID: tenantID, AgentID: input.AgentID, Accepted: input.Accepted, Unsupported: input.Unsupported,
			ObserveOnly: input.ObserveOnly, Executed: input.Executed, Message: input.Message,
		}, observedAt)
		if err != nil {
			return err
		}
		if current.Status == domainresponse.StatusAcknowledged {
			return nil
		}
		if err := tx.Responses().Put(txCtx, current, result.Command); err != nil {
			return err
		}
		return tx.Audits().Append(txCtx, service.audit(result.Command, "acknowledge", "", "", input.Message))
	})
	if err != nil {
		return domainresponse.Acknowledged{}, err
	}
	return result, nil
}
