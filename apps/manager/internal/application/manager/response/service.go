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

type Service struct {
	uow   ports.ResponseUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewService(uow ports.ResponseUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *Service {
	return &Service{uow: uow, clock: clock, ids: ids}
}

type ApprovalCommand struct {
	TenantID   string
	ResponseID string
	AgentID    string
	Approved   bool
	Role       string
	Reason     string
}

func (service *Service) Approve(ctx context.Context, request managerapp.RequestContext, command ApprovalCommand) (domainresponse.Command, error) {
	if err := authorizeApproval(request, command.Role); err != nil {
		return domainresponse.Command{}, err
	}
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return domainresponse.Command{}, failure.New(failure.Internal, "response service is incomplete")
	}
	if strings.TrimSpace(command.TenantID) != "" && command.TenantID != request.Actor.TenantID.String() {
		return domainresponse.Command{}, failure.New(failure.PermissionDenied, "response tenant does not match actor tenant")
	}
	var pending domainresponse.Command
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ResponseTransaction) error {
		current, err := tx.Responses().Get(txCtx, request.Actor.TenantID, strings.TrimSpace(command.ResponseID))
		if err != nil {
			return err
		}
		if command.AgentID != "" && current.AgentID != command.AgentID {
			return failure.New(failure.NotFound, "response command not found")
		}
		now := service.clock.Now()
		pending, err = current.Decide(domainresponse.Approval{
			Actor: request.Actor.Subject, Role: command.Role, Approved: command.Approved, Reason: command.Reason,
		}, now)
		if err != nil {
			return err
		}
		if len(pending.Approvals) == len(current.Approvals) {
			return nil
		}
		if err := tx.Responses().Put(txCtx, current, pending); err != nil {
			return err
		}
		return tx.Audits().Append(txCtx, domainresponse.AuditRecord{
			ID: service.ids.New(), TenantID: pending.TenantID, ResponseID: pending.ID, Action: "approve",
			Actor: request.Actor.Subject, Role: command.Role, Approved: command.Approved, Reason: command.Reason,
			Status: pending.Status, OccurredAt: now,
		})
	})
	if err != nil {
		return domainresponse.Command{}, err
	}
	return pending, nil
}

func authorizeApproval(request managerapp.RequestContext, role string) error {
	if strings.TrimSpace(role) == string(tenant.RoleAdmin) {
		return request.Actor.Require(tenant.RoleAdmin)
	}
	return request.Actor.Require(tenant.RoleOperator)
}
