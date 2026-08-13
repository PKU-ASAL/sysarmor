package control

import (
	"context"
	"fmt"
	"strings"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CreateCommand struct {
	CommandID      string
	TenantID       string
	AgentID        string
	Type           domaincontrol.CommandType
	PolicyID       string
	PolicyVersion  uint64
	ContentRef     string
	ContentKind    string
	ContentVersion string
	Payload        []byte
	Reason         string
}

type CreateEvidenceCommand struct {
	RequestID  string
	TenantID   string
	AgentID    string
	IncidentID string
	Labels     map[string]string
	Target     string
	Reason     string
}

type Action string

const (
	ActionCancel Action = "cancel"
	ActionRetry  Action = "retry"
	ActionExpire Action = "expire"
)

type ActionCommand struct {
	TenantID  string
	CommandID string
	AgentID   string
	Action    Action
	Reason    string
}

type ManagementService struct {
	uow   ports.ControlUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewManagementService(uow ports.ControlUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *ManagementService {
	return &ManagementService{uow: uow, clock: clock, ids: ids}
}

func (service *ManagementService) CreateCommand(ctx context.Context, request managerapp.RequestContext, command CreateCommand) (domaincontrol.Command, error) {
	tenantID, err := service.authorize(request, command.TenantID)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	now := service.clock.Now()
	commandID := strings.TrimSpace(command.CommandID)
	if commandID == "" {
		commandID = service.ids.New()
	}
	value, err := domaincontrol.NewCommand(domaincontrol.Command{
		ID: commandID, TenantID: tenantID, AgentID: command.AgentID, Type: command.Type,
		PolicyID: command.PolicyID, PolicyVersion: command.PolicyVersion, ContentRef: command.ContentRef,
		ContentKind: command.ContentKind, ContentVersion: command.ContentVersion,
		Payload: command.Payload, Actor: request.Actor.Subject, Reason: command.Reason,
	}, now)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	var pending domaincontrol.Command
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		pending, err = tx.Commands().Create(txCtx, value)
		if err != nil {
			return fmt.Errorf("create control command: %w", err)
		}
		return appendControlAudit(txCtx, tx, service.audit(pending, "create", request.Actor.Subject, command.Reason, now))
	})
	if err != nil {
		return domaincontrol.Command{}, err
	}
	return pending, nil
}

func (service *ManagementService) CreateEvidence(ctx context.Context, request managerapp.RequestContext, command CreateEvidenceCommand) (domaincontrol.EvidencePullback, error) {
	tenantID, err := service.authorize(request, command.TenantID)
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	requestID := strings.TrimSpace(command.RequestID)
	if requestID == "" {
		requestID = service.ids.New()
	}
	now := service.clock.Now()
	value, err := domaincontrol.NewEvidencePullback(domaincontrol.EvidencePullback{
		ID: requestID, TenantID: tenantID, AgentID: command.AgentID, IncidentID: command.IncidentID,
		Labels: command.Labels, Target: command.Target, Reason: command.Reason, Actor: request.Actor.Subject,
	}, now)
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	var pending domaincontrol.EvidencePullback
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		pending, err = tx.Evidence().Create(txCtx, value)
		if err != nil {
			return fmt.Errorf("create evidence pullback: %w", err)
		}
		audit := domaincontrol.AuditRecord{ID: service.ids.New(), TenantID: tenantID, ResourceID: pending.ID,
			Action: "create_evidence", Actor: request.Actor.Subject, Reason: command.Reason,
			Status: string(pending.Status), OccurredAt: now}
		return appendControlAudit(txCtx, tx, audit)
	})
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	return pending, nil
}

func (service *ManagementService) Act(ctx context.Context, request managerapp.RequestContext, command ActionCommand) (domaincontrol.Command, error) {
	tenantID, err := service.authorize(request, command.TenantID)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	var pending domaincontrol.Command
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		current, err := tx.Commands().Get(txCtx, tenantID, strings.TrimSpace(command.CommandID))
		if err != nil {
			return err
		}
		if command.AgentID != "" && current.AgentID != command.AgentID {
			return failure.New(failure.NotFound, "control command not found")
		}
		pending, err = applyAction(current, command, request.Actor.Subject, service.clock.Now())
		if err != nil {
			return err
		}
		if err := tx.Commands().Put(txCtx, current, pending); err != nil {
			return err
		}
		return appendControlAudit(txCtx, tx, service.audit(pending, string(command.Action), request.Actor.Subject, command.Reason, pending.UpdatedAt))
	})
	if err != nil {
		return domaincontrol.Command{}, err
	}
	return pending, nil
}

func (service *ManagementService) authorize(request managerapp.RequestContext, rawTenant string) (tenant.ID, error) {
	if err := request.Actor.Require(tenant.RoleAdmin); err != nil {
		return "", err
	}
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return "", failure.New(failure.Internal, "control management service is incomplete")
	}
	if strings.TrimSpace(rawTenant) != "" && rawTenant != request.Actor.TenantID.String() {
		return "", failure.New(failure.PermissionDenied, "control tenant does not match actor tenant")
	}
	return request.Actor.TenantID, nil
}

func (service *ManagementService) audit(value domaincontrol.Command, action, actor, reason string, now time.Time) domaincontrol.AuditRecord {
	return domaincontrol.AuditRecord{ID: service.ids.New(), TenantID: value.TenantID, ResourceID: value.ID,
		Action: action, Actor: actor, Reason: reason, Status: string(value.Status), OccurredAt: now}
}

func applyAction(value domaincontrol.Command, command ActionCommand, actor string, now time.Time) (domaincontrol.Command, error) {
	switch command.Action {
	case ActionCancel:
		return value.Cancel(actor, command.Reason, now), nil
	case ActionRetry:
		return value.Retry(actor, command.Reason, now), nil
	case ActionExpire:
		return value.Expire(command.Reason, now), nil
	default:
		return domaincontrol.Command{}, failure.New(failure.InvalidArgument, "control command action is unsupported")
	}
}

func appendControlAudit(ctx context.Context, tx ports.ControlTransaction, audit domaincontrol.AuditRecord) error {
	if err := tx.Audits().Append(ctx, audit); err != nil {
		return fmt.Errorf("append control audit: %w", err)
	}
	return nil
}
