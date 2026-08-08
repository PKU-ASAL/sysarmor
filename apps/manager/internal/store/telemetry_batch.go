package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
)

func (s *Store) ClaimTelemetryBatch(ctx context.Context, tenantID, batchID string, leaseUntil time.Time) (BatchClaim, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(batchID) == "" {
		return BatchBusy, fmt.Errorf("tenant_id and batch_id are required")
	}
	backend, baseCtx := s.backendCtx()
	if batchBackend, ok := backend.(TelemetryBatchBackend); ok {
		if ctx == nil {
			ctx = baseCtx
		}
		return batchBackend.ClaimTelemetryBatch(ctx, tenantID, batchID, leaseUntil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TelemetryBatches == nil {
		s.TelemetryBatches = map[string]TelemetryBatchRecord{}
	}
	key := telemetryBatchKey(tenantID, batchID)
	record, exists := s.TelemetryBatches[key]
	if exists && record.Status == "completed" {
		return BatchDuplicate, nil
	}
	if exists && record.LeaseUntil.After(time.Now().UTC()) {
		return BatchBusy, nil
	}
	s.TelemetryBatches[key] = TelemetryBatchRecord{TenantID: tenantID, BatchID: batchID, Status: "processing", LeaseUntil: leaseUntil}
	if err := s.persistFileLocked(); err != nil {
		if exists {
			s.TelemetryBatches[key] = record
		} else {
			delete(s.TelemetryBatches, key)
		}
		return BatchBusy, fmt.Errorf("persist telemetry batch claim: %w", err)
	}
	return BatchClaimed, nil
}

func (s *Store) CommitTelemetryBatch(ctx context.Context, delta TelemetryBatchDelta) error {
	if strings.TrimSpace(delta.TenantID) == "" || strings.TrimSpace(delta.BatchID) == "" {
		return fmt.Errorf("tenant_id and batch_id are required")
	}
	backend, baseCtx := s.backendCtx()
	if batchBackend, ok := backend.(TelemetryBatchBackend); ok {
		if ctx == nil {
			ctx = baseCtx
		}
		return batchBackend.CommitTelemetryBatch(ctx, delta)
	}
	return s.commitLocalTelemetryBatch(delta)
}

func (s *Store) AbandonTelemetryBatch(ctx context.Context, tenantID, batchID string, leaseUntil time.Time) error {
	backend, baseCtx := s.backendCtx()
	if batchBackend, ok := backend.(TelemetryBatchBackend); ok {
		if ctx == nil {
			ctx = baseCtx
		}
		return batchBackend.AbandonTelemetryBatch(ctx, tenantID, batchID, leaseUntil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := telemetryBatchKey(tenantID, batchID)
	record, ok := s.TelemetryBatches[key]
	if ok && record.Status == "processing" && record.LeaseUntil.Equal(leaseUntil) {
		delete(s.TelemetryBatches, key)
		return s.persistFileLocked()
	}
	return nil
}

func (s *Store) commitLocalTelemetryBatch(delta TelemetryBatchDelta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := telemetryBatchKey(delta.TenantID, delta.BatchID)
	record, exists := s.TelemetryBatches[key]
	if !exists || record.Status != "processing" || !record.LeaseUntil.Equal(delta.LeaseUntil) {
		return fmt.Errorf("telemetry batch is not processing")
	}
	previousMetrics := s.MetricsByTenant[delta.TenantID]
	previousRarity := s.RarityByTenant[delta.TenantID].Snapshot()
	s.MetricsByTenant = ensureMetricsMap(s.MetricsByTenant)
	s.RarityByTenant = ensureRarityMap(s.RarityByTenant)
	s.MetricsByTenant[delta.TenantID] = MergeMetrics(previousMetrics, delta.Metrics)
	baseline := previousRarity.Snapshot()
	baseline.Merge(delta.Rarity)
	s.RarityByTenant[delta.TenantID] = baseline
	record.Status = "completed"
	record.CompletedAt = time.Now().UTC()
	s.TelemetryBatches[key] = record
	if err := s.persistFileLocked(); err != nil {
		s.MetricsByTenant[delta.TenantID] = previousMetrics
		s.RarityByTenant[delta.TenantID] = previousRarity
		record.Status = "processing"
		record.CompletedAt = time.Time{}
		s.TelemetryBatches[key] = record
		return fmt.Errorf("persist telemetry batch commit: %w", err)
	}
	return nil
}

func ensureMetricsMap(input map[string]Metrics) map[string]Metrics {
	if input == nil {
		return map[string]Metrics{}
	}
	return input
}

func ensureRarityMap(input map[string]rarity.Baseline) map[string]rarity.Baseline {
	if input == nil {
		return map[string]rarity.Baseline{}
	}
	return input
}

func telemetryBatchKey(tenantID, batchID string) string {
	return tenantID + "\x00" + batchID
}
