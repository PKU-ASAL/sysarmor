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
	spool     ports.TelemetrySpool
	sender    ports.TelemetrySender
	lifecycle *domaintelemetry.CandidateLifecycle
}

func NewDelivery(spool ports.TelemetrySpool, sender ports.TelemetrySender, lifecycle ...*domaintelemetry.CandidateLifecycle) *Delivery {
	delivery := &Delivery{spool: spool, sender: sender}
	if len(lifecycle) > 0 {
		delivery.lifecycle = lifecycle[0]
	}
	return delivery
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
		candidates := stored.Batch.ModelCandidates
		delivery.lifecycle.RecordDeliveryAttempted(candidates)
		outcome, err := delivery.sender.Send(ctx, stored.Batch)
		if err != nil {
			delivery.lifecycle.RecordDeliveryError(candidates, err.Error())
			return err
		}
		delivery.recordOutcome(outcome, candidates)
		if outcome != domaintelemetry.DeliveryAccepted && outcome != domaintelemetry.DeliveryDuplicate {
			return fmt.Errorf("batch %s was not committed", stored.Position.BatchID)
		}
		if err := delivery.spool.SaveCheckpoint(ctx, stored.Position); err != nil {
			return err
		}
	}
	return nil
}

func (delivery *Delivery) recordOutcome(outcome domaintelemetry.DeliveryOutcome, candidates uint64) {
	if delivery.lifecycle == nil || candidates == 0 {
		return
	}
	if outcome == domaintelemetry.DeliveryAccepted {
		delivery.lifecycle.RecordGatewayAccepted(candidates)
	} else if outcome == domaintelemetry.DeliveryDuplicate {
		delivery.lifecycle.RecordGatewayDuplicateAck(candidates)
	} else if outcome == domaintelemetry.DeliveryRejected {
		delivery.lifecycle.RecordGatewayRejected(candidates)
	} else if outcome == domaintelemetry.DeliveryRetryable {
		delivery.lifecycle.RecordGatewayRetryable(candidates)
	}
}

func foreignIdentity(batch domaintelemetry.Batch, scope DeliveryScope) bool {
	return scope.TenantID != "" && (batch.TenantID != scope.TenantID || batch.AgentID != scope.AgentID)
}
