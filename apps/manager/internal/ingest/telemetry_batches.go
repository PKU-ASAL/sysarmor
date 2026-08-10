package ingestworker

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type storeTelemetryBatches struct{ store *store.Store }

func (b storeTelemetryBatches) Claim(ctx context.Context, tenantID, batchID string, lease time.Duration) (ports.TelemetryClaim, string, error) {
	claim, token, err := b.store.ClaimTelemetryBatch(ctx, tenantID, batchID, lease)
	return ports.TelemetryClaim(claim), token, err
}

func (b storeTelemetryBatches) Commit(ctx context.Context, delta ports.TelemetryBatchDelta) error {
	return b.store.CommitTelemetryBatch(ctx, store.TelemetryBatchDelta{
		TenantID: delta.TenantID, BatchID: delta.BatchID, ClaimToken: delta.ClaimToken,
		Metrics: store.Metrics{
			DataBatchesAppended: delta.Metrics.DataBatches, EventsIngested: delta.Metrics.Events,
			EndpointSignalsIngested: delta.Metrics.EndpointSignals, CloudSignalsEmitted: delta.Metrics.CloudSignals,
			SignalsEmitted: delta.Metrics.Signals, IncidentsCreated: delta.Metrics.Incidents,
			LastConvergenceLatencyMs: delta.Metrics.LastLatencyMs, MaxConvergenceLatencyMs: delta.Metrics.MaxLatencyMs,
			TotalConvergenceLatencyMs: delta.Metrics.TotalLatencyMs, AverageConvergenceLatency: delta.Metrics.AverageLatencyMs,
		},
		Rarity: rarity.Baseline{WorkloadCounts: delta.Rarity.WorkloadCounts},
	})
}

func (b storeTelemetryBatches) Abandon(ctx context.Context, tenantID, batchID, token string) error {
	return b.store.AbandonTelemetryBatch(ctx, tenantID, batchID, token)
}
