package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	workerprocessing "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/worker/processing"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

const batchClaimLease = 30 * time.Second

type ProcessBatch struct {
	decoder    ports.BatchDecoder
	projector  ports.BatchProjector
	history    ports.HistoryReader
	rarity     ports.RarityReader
	batches    ports.TelemetryBatches
	policies   ports.DetectionPolicyReader
	claimLease time.Duration
}

type ProcessBatchResult struct {
	AcceptedEvents, AcceptedSignals int
	CloudSignals, Incidents         int
	Duplicate                       bool
}

func NewProcessBatch(decoder ports.BatchDecoder, projector ports.BatchProjector, history ports.HistoryReader, rarityReader ports.RarityReader, batches ports.TelemetryBatches, policies ports.DetectionPolicyReader) *ProcessBatch {
	return &ProcessBatch{decoder: decoder, projector: projector, history: history, rarity: rarityReader, batches: batches, policies: policies, claimLease: batchClaimLease}
}

func (service *ProcessBatch) Process(ctx context.Context, message ports.RawMessage) error {
	if service == nil || service.decoder == nil {
		return fmt.Errorf("process batch requires decoder")
	}
	batch, err := service.decoder.Decode(message)
	if err != nil {
		return err
	}
	_, err = service.Execute(ctx, batch)
	return err
}

func (service *ProcessBatch) Execute(ctx context.Context, batch ports.DataBatch) (result ProcessBatchResult, err error) {
	if err := service.validate(batch); err != nil {
		return result, err
	}
	claim, token, err := service.batches.Claim(ctx, batch.TenantID.String(), batch.ID, service.claimLease)
	if err != nil {
		return result, fmt.Errorf("claim telemetry batch: %w", err)
	}
	if claim == ports.TelemetryDuplicate {
		return ProcessBatchResult{Duplicate: true}, nil
	}
	if claim == ports.TelemetryBusy {
		return result, fmt.Errorf("telemetry batch is already processing")
	}
	committed := false
	defer func() {
		if !committed {
			if abandonErr := service.batches.Abandon(ctx, batch.TenantID.String(), batch.ID, token); abandonErr != nil {
				err = errors.Join(err, fmt.Errorf("abandon telemetry batch: %w", abandonErr))
			}
		}
	}()
	result, err = service.executeWithRenewal(ctx, batch, token)
	committed = err == nil
	return result, err
}

func (service *ProcessBatch) executeWithRenewal(ctx context.Context, batch ports.DataBatch, token string) (ProcessBatchResult, error) {
	workCtx, cancel := context.WithCancel(ctx)
	renewed := make(chan error, 1)
	go service.renewClaim(workCtx, batch, token, cancel, renewed)
	result, delta, err := service.executeClaimed(workCtx, batch, token)
	if err == nil {
		err = service.batches.Commit(workCtx, delta)
	}
	cancel()
	if renewErr := <-renewed; renewErr != nil {
		return ProcessBatchResult{}, errors.Join(err, fmt.Errorf("renew telemetry claim: %w", renewErr))
	}
	if err != nil {
		return ProcessBatchResult{}, err
	}
	return result, nil
}

func (service *ProcessBatch) renewClaim(ctx context.Context, batch ports.DataBatch, token string, cancel context.CancelFunc, result chan<- error) {
	ticker := time.NewTicker(service.claimLease / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			result <- nil
			return
		case <-ticker.C:
			if err := service.batches.Renew(ctx, batch.TenantID.String(), batch.ID, token, service.claimLease); err != nil {
				cancel()
				result <- err
				return
			}
		}
	}
}

func (service *ProcessBatch) executeClaimed(ctx context.Context, batch ports.DataBatch, token string) (ProcessBatchResult, ports.TelemetryBatchDelta, error) {
	started := time.Now()
	baseline, err := service.rarity.Rarity(ctx, batch.TenantID)
	if err != nil {
		return ProcessBatchResult{}, ports.TelemetryBatchDelta{}, fmt.Errorf("load tenant rarity baseline: %w", err)
	}
	engine := workerprocessing.NewEngine()
	engine.SetRarityBaseline(rarity.Baseline{WorkloadCounts: baseline.WorkloadCounts})
	analysis, err := service.recomputeTouchedScopes(ctx, engine, batch)
	if err != nil {
		return ProcessBatchResult{}, ports.TelemetryBatchDelta{}, err
	}
	projection := batchProjection(batch, analysis)
	if err := service.projector.Project(ctx, projection); err != nil {
		return ProcessBatchResult{}, ports.TelemetryBatchDelta{}, err
	}
	result := processResult(batch, analysis)
	delta := telemetryBatchDelta(batch, token, result, time.Since(started))
	return result, delta, nil
}

func (service *ProcessBatch) validate(batch ports.DataBatch) error {
	if service == nil || service.projector == nil || service.history == nil || service.rarity == nil || service.batches == nil || service.policies == nil || service.claimLease <= 0 {
		return fmt.Errorf("process batch dependencies are incomplete")
	}
	if batch.TenantID == "" || batch.AgentID == "" || batch.ID == "" {
		return fmt.Errorf("data batch identity is required")
	}
	return nil
}
