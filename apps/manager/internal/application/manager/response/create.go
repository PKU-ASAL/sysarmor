package response

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CreateCommand struct {
	Value        domainresponse.Command
	Policy       domainresponse.Policy
	Runtime      domainresponse.Scope
	RuntimeKnown bool
}

type DecisionCommand struct {
	SignalID string
	TenantID string
	AgentID  string
	Scope    domainresponse.Scope
	Target   string
}

func (service *Service) Create(ctx context.Context, request managerapp.RequestContext, input CreateCommand) (domainresponse.PrepareResult, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainresponse.PrepareResult{}, err
	}
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return domainresponse.PrepareResult{}, failure.New(failure.Internal, "response service is incomplete")
	}
	if !input.Value.TenantID.IsZero() && input.Value.TenantID != request.Actor.TenantID {
		return domainresponse.PrepareResult{}, failure.New(failure.PermissionDenied, "response tenant does not match actor tenant")
	}
	input.Value.TenantID, input.Value.Actor = request.Actor.TenantID, request.Actor.Subject
	if strings.TrimSpace(input.Value.ID) == "" {
		input.Value.ID = service.ids.New()
	}
	result, err := domainresponse.Prepare(input.Value, input.Policy, input.Runtime, input.RuntimeKnown, service.clock.Now())
	if err != nil {
		return domainresponse.PrepareResult{}, err
	}
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ResponseTransaction) error {
		result.Command, err = tx.Responses().Create(txCtx, result.Command)
		if err != nil {
			return err
		}
		action := "create"
		if !result.Allowed {
			action = "deny"
		}
		return tx.Audits().Append(txCtx, service.audit(result.Command, action, request.Actor.Subject, "", result.Reason))
	})
	if err != nil {
		return domainresponse.PrepareResult{}, err
	}
	return result, nil
}

func (service *Service) audit(command domainresponse.Command, action, actor, role, reason string) domainresponse.AuditRecord {
	return domainresponse.AuditRecord{
		ID: service.ids.New(), TenantID: command.TenantID, ResponseID: command.ID, Action: action,
		Actor: actor, Role: role, Reason: reason, Status: command.Status, OccurredAt: command.UpdatedAt,
	}
}
