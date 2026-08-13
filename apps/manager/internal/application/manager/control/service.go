package control

import (
	"context"
	"fmt"
	"time"

	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type AcknowledgeCommand struct {
	TenantID      string
	AgentID       string
	CommandID     string
	Status        domaincontrol.CommandStatus
	Message       string
	PolicyID      string
	PolicyVersion uint64
	Report        string
	ObservedAt    time.Time
}

type CompleteEvidenceCommand struct {
	TenantID   string
	AgentID    string
	RequestID  string
	OK         bool
	Message    string
	Evidence   []byte
	ObservedAt time.Time
}

type ResultService struct {
	uow   ports.ControlUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewResultService(uow ports.ControlUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *ResultService {
	return &ResultService{uow: uow, clock: clock, ids: ids}
}

func (service *ResultService) Acknowledge(ctx context.Context, command AcknowledgeCommand) (domaincontrol.Command, error) {
	tenantID, err := service.validate(command.TenantID)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	var pending domaincontrol.Command
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		current, err := tx.Commands().Get(txCtx, tenantID, command.CommandID)
		if err != nil {
			return fmt.Errorf("get control command: %w", err)
		}
		if current.AgentID != command.AgentID {
			return failure.New(failure.Conflict, "control command agent does not match")
		}
		pending, err = current.Acknowledge(domaincontrol.Acknowledgement{Status: command.Status, Message: command.Message,
			PolicyID: command.PolicyID, PolicyVersion: command.PolicyVersion, Report: command.Report}, service.observedAt(command.ObservedAt))
		if err != nil {
			return err
		}
		return putCommandResult(txCtx, tx, current, pending, service.ids.New(), "acknowledge")
	})
	if err != nil {
		return domaincontrol.Command{}, err
	}
	return pending, nil
}

func (service *ResultService) CompleteEvidence(ctx context.Context, command CompleteEvidenceCommand) (domaincontrol.EvidencePullback, error) {
	tenantID, err := service.validate(command.TenantID)
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	var pending domaincontrol.EvidencePullback
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		current, err := tx.Evidence().Get(txCtx, tenantID, command.RequestID)
		if err != nil {
			return fmt.Errorf("get evidence pullback: %w", err)
		}
		pending, err = current.Complete(domaincontrol.EvidenceResult{
			TenantID: tenantID, AgentID: command.AgentID, OK: command.OK, Message: command.Message,
			Evidence: command.Evidence,
		}, service.observedAt(command.ObservedAt))
		if err != nil {
			return err
		}
		return putEvidenceResult(txCtx, tx, current, pending, service.ids.New())
	})
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	return pending, nil
}

func (service *ResultService) observedAt(value time.Time) time.Time {
	if value.IsZero() {
		return service.clock.Now()
	}
	return value.UTC()
}

func (service *ResultService) validate(rawTenant string) (tenant.ID, error) {
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return "", failure.New(failure.Internal, "control result service is incomplete")
	}
	return tenant.NewID(rawTenant)
}

func putCommandResult(ctx context.Context, tx ports.ControlTransaction, current, command domaincontrol.Command, auditID, action string) error {
	if err := tx.Commands().Put(ctx, current, command); err != nil {
		return fmt.Errorf("put control command: %w", err)
	}
	return tx.Audits().Append(ctx, domaincontrol.AuditRecord{
		ID: auditID, TenantID: command.TenantID, ResourceID: command.ID, Action: action,
		Status: string(command.Status), OccurredAt: command.UpdatedAt,
	})
}

func putEvidenceResult(ctx context.Context, tx ports.ControlTransaction, current, value domaincontrol.EvidencePullback, auditID string) error {
	if err := tx.Evidence().Put(ctx, current, value); err != nil {
		return fmt.Errorf("put evidence pullback: %w", err)
	}
	return tx.Audits().Append(ctx, domaincontrol.AuditRecord{
		ID: auditID, TenantID: value.TenantID, ResourceID: value.ID, Action: "complete_evidence",
		Status: string(value.Status), OccurredAt: value.UpdatedAt,
	})
}
