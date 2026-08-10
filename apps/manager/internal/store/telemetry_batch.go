package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
)

func (s *Store) ClaimTelemetryBatch(ctx context.Context, tenantID, batchID string, leaseDuration time.Duration) (BatchClaim, string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(batchID) == "" || leaseDuration.Milliseconds() <= 0 {
		return BatchBusy, "", fmt.Errorf("tenant_id, batch_id, and positive lease duration are required")
	}
	claimToken, err := newClaimToken()
	if err != nil {
		return BatchBusy, "", err
	}
	backend, baseCtx := s.backendCtx()
	if batchBackend, ok := backend.(TelemetryBatchBackend); ok {
		if ctx == nil {
			ctx = baseCtx
		}
		claim, err := batchBackend.ClaimTelemetryBatch(ctx, tenantID, batchID, claimToken, leaseDuration)
		return claim, claimToken, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TelemetryBatches == nil {
		s.TelemetryBatches = map[string]TelemetryBatchRecord{}
	}
	key := telemetryBatchKey(tenantID, batchID)
	record, exists := s.TelemetryBatches[key]
	if exists && record.Status == "completed" {
		return BatchDuplicate, "", nil
	}
	if exists && record.LeaseUntil.After(time.Now().UTC()) {
		return BatchBusy, "", nil
	}
	s.TelemetryBatches[key] = TelemetryBatchRecord{TenantID: tenantID, BatchID: batchID, Status: "processing", ClaimToken: claimToken, LeaseUntil: time.Now().UTC().Add(leaseDuration)}
	if err := s.persistFileLocked(); err != nil {
		if exists {
			s.TelemetryBatches[key] = record
		} else {
			delete(s.TelemetryBatches, key)
		}
		return BatchBusy, "", fmt.Errorf("persist telemetry batch claim: %w", err)
	}
	return BatchClaimed, claimToken, nil
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

func (s *Store) AbandonTelemetryBatch(ctx context.Context, tenantID, batchID, claimToken string) error {
	backend, baseCtx := s.backendCtx()
	if batchBackend, ok := backend.(TelemetryBatchBackend); ok {
		if ctx == nil {
			ctx = baseCtx
		}
		return batchBackend.AbandonTelemetryBatch(ctx, tenantID, batchID, claimToken)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := telemetryBatchKey(tenantID, batchID)
	record, ok := s.TelemetryBatches[key]
	if ok && record.Status == "processing" && record.ClaimToken == claimToken {
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
	if !exists || record.Status != "processing" || record.ClaimToken != delta.ClaimToken {
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

func newClaimToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate telemetry claim token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
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
