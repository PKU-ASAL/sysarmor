package control

import (
	"context"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type DeliveryService struct {
	uow   ports.ControlUnitOfWork
	clock ports.Clock
	ids   ports.IDGenerator
}

func NewDeliveryService(uow ports.ControlUnitOfWork, clock ports.Clock, ids ports.IDGenerator) *DeliveryService {
	return &DeliveryService{uow: uow, clock: clock, ids: ids}
}

func (service *DeliveryService) MarkSent(ctx context.Context, rawTenant, agentID, commandID string) error {
	if service == nil || service.uow == nil || service.clock == nil || service.ids == nil {
		return failure.New(failure.Internal, "control delivery service is incomplete")
	}
	tenantID, err := tenant.NewID(rawTenant)
	if err != nil {
		return err
	}
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(commandID) == "" {
		return failure.New(failure.InvalidArgument, "control delivery identity is required")
	}
	return service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ControlTransaction) error {
		current, err := tx.Commands().Get(txCtx, tenantID, commandID)
		if err != nil {
			return fmt.Errorf("get control command: %w", err)
		}
		if current.AgentID != agentID {
			return failure.New(failure.Conflict, "control command agent does not match")
		}
		pending := current.MarkSent(service.clock.Now())
		return putCommandResult(txCtx, tx, current, pending, service.ids.New(), "send")
	})
}
