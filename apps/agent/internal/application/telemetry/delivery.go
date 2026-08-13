package telemetry

import (
	"context"
	"fmt"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type DeliveryScope struct {
	FromSequence uint64
	TenantID     string
	AgentID      string
}

type Delivery struct {
	spool  ports.TelemetrySpool
	sender ports.TelemetrySender
}

func NewDelivery(spool ports.TelemetrySpool, sender ports.TelemetrySender) *Delivery {
	return &Delivery{spool: spool, sender: sender}
}

func (delivery *Delivery) Run(ctx context.Context, scope DeliveryScope) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := delivery.DeliverAvailable(ctx, scope)
		if ctx.Err() != nil {
			return
		}
		delay := 500 * time.Millisecond
		if err != nil {
			delay = backoff
			backoff = min(backoff*2, 30*time.Second)
		} else {
			backoff = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (delivery *Delivery) DeliverAvailable(ctx context.Context, scope DeliveryScope) error {
	if delivery == nil || delivery.spool == nil || delivery.sender == nil {
		return fmt.Errorf("telemetry delivery is not initialized")
	}
	checkpoint, err := delivery.spool.Checkpoint(ctx)
	if err != nil {
		return err
	}
	batches, err := delivery.spool.Read(ctx, scope.FromSequence, 1000)
	if err != nil {
		return err
	}
	for _, stored := range batches {
		if domaintelemetry.Before(stored.Position, checkpoint) {
			continue
		}
		if foreignIdentity(stored.Batch, scope) {
			if err := delivery.spool.SaveCheckpoint(ctx, stored.Position); err != nil {
				return err
			}
			continue
		}
		outcome, err := delivery.sender.Send(ctx, stored.Batch)
		if err != nil {
			return err
		}
		if outcome != domaintelemetry.DeliveryAccepted && outcome != domaintelemetry.DeliveryDuplicate {
			return fmt.Errorf("batch %s was not committed", stored.Position.BatchID)
		}
		if err := delivery.spool.SaveCheckpoint(ctx, stored.Position); err != nil {
			return err
		}
	}
	return nil
}

func foreignIdentity(batch domaintelemetry.Batch, scope DeliveryScope) bool {
	return scope.TenantID != "" && (batch.TenantID != scope.TenantID || batch.AgentID != scope.AgentID)
}
