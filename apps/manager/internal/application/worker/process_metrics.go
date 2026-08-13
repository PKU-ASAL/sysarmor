package worker

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func batchProjection(batch ports.DataBatch, analysis batchAnalysis) ports.BatchProjection {
	return ports.BatchProjection{
		Source: batch.Source, TenantID: batch.TenantID, AgentID: batch.AgentID, ObservedAt: batch.CreatedAt,
		Events: batch.Events, Signals: batch.Signals, CloudSignals: analysis.cloudSignals, Incidents: analysis.incidents,
	}
}

func processResult(batch ports.DataBatch, analysis batchAnalysis) ProcessBatchResult {
	return ProcessBatchResult{
		AcceptedEvents: len(batch.Events), AcceptedSignals: len(batch.Signals),
		CloudSignals: len(analysis.cloudSignals), Incidents: len(analysis.incidents),
	}
}

func telemetryBatchDelta(batch ports.DataBatch, token string, result ProcessBatchResult, latency time.Duration) ports.TelemetryBatchDelta {
	latencyMS := uint64(latency.Milliseconds())
	metrics := ports.TelemetryMetrics{
		DataBatches: 1, Events: uint64(result.AcceptedEvents), EndpointSignals: uint64(result.AcceptedSignals),
		CloudSignals: uint64(result.CloudSignals), Signals: uint64(result.AcceptedSignals + result.CloudSignals),
		Incidents: uint64(result.Incidents), LastLatencyMs: latencyMS, MaxLatencyMs: latencyMS,
		TotalLatencyMs: latencyMS, AverageLatencyMs: float64(latencyMS),
	}
	baseline := rarity.Baseline{}
	signals := make([]domaintelemetry.Signal, 0, len(batch.Signals))
	for _, observed := range batch.Signals {
		signals = append(signals, observed.Signal)
	}
	baseline.Observe(signals)
	return ports.TelemetryBatchDelta{
		TenantID: batch.TenantID.String(), BatchID: batch.ID, ClaimToken: token,
		Metrics: metrics, Rarity: identity.RarityBaseline{WorkloadCounts: baseline.WorkloadCounts},
	}
}
