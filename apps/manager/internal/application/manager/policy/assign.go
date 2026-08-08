package policy

import (
	"context"
	"fmt"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type AssignPolicyCommand struct {
	PolicyID  domainpolicy.ID
	Version   domainpolicy.Version
	Target    domainpolicy.Target
	Downlink  bool
	CommandID string
	Reason    string
}

type AssignPolicyResult struct {
	Assignment domainpolicy.Assignment
	Control    *ports.PolicyControlCommand
}

type AssignService struct {
	uow   ports.PolicyUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewAssignService(uow ports.PolicyUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *AssignService {
	return &AssignService{uow: uow, clock: clock, ids: ids}
}

func (service *AssignService) Execute(ctx context.Context, request managerapp.RequestContext, command AssignPolicyCommand) (AssignPolicyResult, error) {
	var result AssignPolicyResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		value, err := tx.Policies().Get(txCtx, request.Actor.TenantID, command.PolicyID, command.Version)
		if err != nil {
			return fmt.Errorf("get policy: %w", err)
		}
		assignment, err := domainpolicy.Assign(value, command.Target, request.Actor, service.clock.Now())
		if err != nil {
			return err
		}
		assignment.ID = service.ids.New()
		if err := tx.Assignments().Put(txCtx, assignment); err != nil {
			return fmt.Errorf("put policy assignment: %w", err)
		}
		record := assignmentAudit(assignment, request, command.Reason, service.ids.New())
		if err := tx.Audits().Append(txCtx, assignment.TenantID, record); err != nil {
			return fmt.Errorf("append policy audit: %w", err)
		}
		control, err := service.putControl(txCtx, tx.Controls(), value, assignment, request, command)
		if err != nil {
			return err
		}
		result = AssignPolicyResult{Assignment: assignment, Control: control}
		return nil
	})
	return result, err
}

func (service *AssignService) putControl(ctx context.Context, repo ports.PolicyControlRepository, value domainpolicy.Policy, assignment domainpolicy.Assignment, request managerapp.RequestContext, command AssignPolicyCommand) (*ports.PolicyControlCommand, error) {
	if !command.Downlink {
		return nil, nil
	}
	if strings.TrimSpace(assignment.Target.AgentID) == "" {
		return nil, fmt.Errorf("downlink requires an agent target")
	}
	commandID := command.CommandID
	if commandID == "" {
		commandID = service.ids.New()
	}
	control := ports.PolicyControlCommand{
		ID: commandID, TenantID: assignment.TenantID, AgentID: assignment.Target.AgentID,
		PolicyID: value.ID, PolicyVersion: value.Version, Payload: append([]byte(nil), value.Document...),
		Actor: request.Actor.Subject, Reason: command.Reason, CreatedAt: service.clock.Now(),
	}
	if err := repo.Put(ctx, control); err != nil {
		return nil, fmt.Errorf("put policy control command: %w", err)
	}
	return &control, nil
}

func assignmentAudit(assignment domainpolicy.Assignment, request managerapp.RequestContext, reason, id string) audit.Record {
	return audit.Record{
		ID: id, TenantID: assignment.TenantID, Action: "policy.assign",
		PolicyID: assignment.PolicyID.String(), PolicyVersion: uint64(assignment.PolicyVersion),
		AssignmentID: assignment.ID, Actor: request.Actor.Subject, Reason: reason,
		Status: "success", OccurredAt: assignment.UpdatedAt,
	}
}
