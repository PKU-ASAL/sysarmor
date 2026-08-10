package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func (b *tableBackend) ClaimTelemetryBatch(ctx context.Context, tenantID, batchID, claimToken string, leaseDuration time.Duration) (store.BatchClaim, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(batchID) == "" || strings.TrimSpace(claimToken) == "" || leaseDuration.Milliseconds() <= 0 {
		return store.BatchBusy, fmt.Errorf("tenant_id, batch_id, claim token, and positive lease duration are required")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return store.BatchBusy, fmt.Errorf("begin telemetry batch claim: %w", err)
	}
	defer tx.Rollback()
	claim, err := claimTelemetryBatch(ctx, tx, tenantID, batchID, claimToken, leaseDuration)
	if err != nil {
		return store.BatchBusy, err
	}
	if err := tx.Commit(); err != nil {
		return store.BatchBusy, fmt.Errorf("commit telemetry batch claim: %w", err)
	}
	return claim, nil
}

func claimTelemetryBatch(ctx context.Context, tx *sql.Tx, tenantID, batchID, claimToken string, leaseDuration time.Duration) (store.BatchClaim, error) {
	var status string
	var expired bool
	err := tx.QueryRowContext(ctx, `SELECT status, lease_until <= now() AS expired FROM telemetry_batches
WHERE tenant_id=$1 AND batch_id=$2 FOR UPDATE`, tenantID, batchID).Scan(&status, &expired)
	if err == sql.ErrNoRows {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO telemetry_batches (tenant_id, batch_id, status, claim_token, lease_until)
VALUES ($1,$2,'processing',$3,now()+($4 * interval '1 millisecond')) ON CONFLICT (tenant_id, batch_id) DO NOTHING`, tenantID, batchID, claimToken, leaseDuration.Milliseconds())
		if insertErr != nil {
			return store.BatchBusy, fmt.Errorf("insert telemetry batch claim: %w", insertErr)
		}
		inserted, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return store.BatchBusy, fmt.Errorf("inspect telemetry batch claim insert: %w", rowsErr)
		}
		if inserted == 1 {
			return store.BatchClaimed, nil
		}
		return claimTelemetryBatch(ctx, tx, tenantID, batchID, claimToken, leaseDuration)
	}
	if err != nil {
		return store.BatchBusy, fmt.Errorf("read telemetry batch claim: %w", err)
	}
	if status == "completed" {
		return store.BatchDuplicate, nil
	}
	if !expired {
		return store.BatchBusy, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE telemetry_batches SET claim_token=$3, lease_until=now()+($4 * interval '1 millisecond')
WHERE tenant_id=$1 AND batch_id=$2 AND status='processing'`, tenantID, batchID, claimToken, leaseDuration.Milliseconds())
	return store.BatchClaimed, wrapTelemetryError("renew telemetry batch claim", err)
}

func (b *tableBackend) CommitTelemetryBatch(ctx context.Context, delta store.TelemetryBatchDelta) error {
	if strings.TrimSpace(delta.TenantID) == "" || strings.TrimSpace(delta.BatchID) == "" {
		return fmt.Errorf("tenant_id and batch_id are required")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return b.withTransaction(ctx, func(tx *sql.Tx) error {
		if err := lockProcessingBatch(ctx, tx, delta.TenantID, delta.BatchID, delta.ClaimToken); err != nil {
			return err
		}
		if err := mergeTenantMetrics(ctx, tx, delta.TenantID, delta.Metrics); err != nil {
			return err
		}
		if err := incrementTenantRarity(ctx, tx, delta.TenantID, delta.Rarity); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE telemetry_batches SET status = 'completed', completed_at=now()
WHERE tenant_id=$1 AND batch_id=$2 AND status='processing'`, delta.TenantID, delta.BatchID)
		return wrapTelemetryError("complete telemetry batch", err)
	})
}

func lockProcessingBatch(ctx context.Context, tx *sql.Tx, tenantID, batchID, claimToken string) error {
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM telemetry_batches
WHERE tenant_id=$1 AND batch_id=$2 AND claim_token=$3 FOR UPDATE`, tenantID, batchID, claimToken).Scan(&status); err != nil {
		return fmt.Errorf("lock telemetry batch: %w", err)
	}
	if status != "processing" {
		return fmt.Errorf("telemetry batch is not processing")
	}
	return nil
}

func (b *tableBackend) AbandonTelemetryBatch(ctx context.Context, tenantID, batchID, claimToken string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `DELETE FROM telemetry_batches
WHERE tenant_id=$1 AND batch_id=$2 AND status='processing' AND claim_token=$3`, tenantID, batchID, claimToken)
	return wrapTelemetryError("abandon telemetry batch", err)
}

func mergeTenantMetrics(ctx context.Context, tx *sql.Tx, tenantID string, delta store.Metrics) error {
	empty, _ := json.Marshal(store.Metrics{})
	if _, err := tx.ExecContext(ctx, `INSERT INTO metrics (tenant_id, metric_key, data)
VALUES ($1,'manager',$2) ON CONFLICT (tenant_id, metric_key) DO NOTHING`, tenantID, empty); err != nil {
		return fmt.Errorf("ensure tenant metrics: %w", err)
	}
	current, err := queryMetricsForTenantLocked(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	return projectMetricsForTenant(ctx, tx, tenantID, store.MergeMetrics(current, delta))
}

func queryMetricsForTenantLocked(ctx context.Context, tx *sql.Tx, tenantID string) (store.Metrics, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT data FROM metrics
WHERE tenant_id=$1 AND metric_key='manager' FOR UPDATE`, tenantID).Scan(&raw); err != nil {
		return store.Metrics{}, fmt.Errorf("lock tenant metrics: %w", err)
	}
	var metrics store.Metrics
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return store.Metrics{}, fmt.Errorf("decode tenant metrics: %w", err)
	}
	return metrics, nil
}

func incrementTenantRarity(ctx context.Context, tx *sql.Tx, tenantID string, delta rarity.Baseline) error {
	for workload, signals := range delta.WorkloadCounts {
		for signalName, count := range signals {
			if count == 0 {
				continue
			}
			data, _ := json.Marshal(map[string]any{"workload_key": workload, "signal_name": signalName, "signal_count": count})
			_, err := tx.ExecContext(ctx, `INSERT INTO rarity_baseline (tenant_id, workload_key, signal_name, signal_count, data)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id, workload_key, signal_name) DO UPDATE SET
signal_count = rarity_baseline.signal_count + EXCLUDED.signal_count,
updated_at=now(),
data=jsonb_build_object(
  'workload_key', EXCLUDED.workload_key,
  'signal_name', EXCLUDED.signal_name,
  'signal_count', rarity_baseline.signal_count + EXCLUDED.signal_count
)`, tenantID, workload, signalName, count, data)
			if err != nil {
				return fmt.Errorf("increment tenant rarity: %w", err)
			}
		}
	}
	return nil
}

func wrapTelemetryError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
