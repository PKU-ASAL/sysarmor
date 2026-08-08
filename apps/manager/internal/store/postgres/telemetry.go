package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func projectMetricsForTenant(ctx context.Context, db sqlExecutor, tenantID string, metrics store.Metrics) error {
	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("encode metrics projection: %w", err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO metrics (tenant_id, metric_key, data)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, metric_key) DO UPDATE SET
  updated_at = now(),
  data = EXCLUDED.data
`, tenantID, "manager", data)
	if err != nil {
		return fmt.Errorf("project metrics: %w", err)
	}
	return nil
}

func (b *tableBackend) LoadMetricsForTenant(ctx context.Context, tenantID string) (store.Metrics, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return queryMetricsForTenant(ctx, b.db, tenantID)
}

func queryMetricsForTenant(ctx context.Context, db sqlExecutor, tenantID string) (store.Metrics, error) {
	row := db.QueryRowContext(ctx, `
SELECT data FROM metrics
WHERE tenant_id = $1 AND metric_key = $2
`, tenantID, "manager")
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return store.Metrics{}, nil
		}
		return store.Metrics{}, fmt.Errorf("query metrics: %w", err)
	}
	var metrics store.Metrics
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return store.Metrics{}, fmt.Errorf("decode metrics: %w", err)
	}
	return metrics, nil
}

func projectRarityBaselineForTenant(ctx context.Context, db sqlExecutor, tenantID string, baseline rarity.Baseline) error {
	for workload, signals := range baseline.WorkloadCounts {
		workload = strings.TrimSpace(workload)
		if workload == "" {
			workload = "global"
		}
		for signalName, count := range signals {
			signalName = strings.TrimSpace(signalName)
			if signalName == "" || count == 0 {
				continue
			}
			row := map[string]any{
				"workload_key": workload,
				"signal_name":  signalName,
				"signal_count": count,
			}
			data, err := json.Marshal(row)
			if err != nil {
				return fmt.Errorf("encode rarity baseline projection: %w", err)
			}
			_, err = db.ExecContext(ctx, `
INSERT INTO rarity_baseline (tenant_id, workload_key, signal_name, signal_count, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, workload_key, signal_name) DO UPDATE SET
  signal_count = EXCLUDED.signal_count,
  updated_at = now(),
  data = EXCLUDED.data
`, tenantID, workload, signalName, count, data)
			if err != nil {
				return fmt.Errorf("project rarity baseline: %w", err)
			}
		}
	}
	return nil
}

func (b *tableBackend) LoadRarityForTenant(ctx context.Context, tenantID string) (rarity.Baseline, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	rows, err := b.db.QueryContext(ctx, `
SELECT workload_key, signal_name, signal_count FROM rarity_baseline
WHERE tenant_id = $1
`, tenantID)
	if err != nil {
		return rarity.Baseline{}, fmt.Errorf("query rarity baseline: %w", err)
	}
	defer rows.Close()
	baseline := rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{}}
	for rows.Next() {
		var workload, signalName string
		var count uint64
		if err := rows.Scan(&workload, &signalName, &count); err != nil {
			return rarity.Baseline{}, fmt.Errorf("scan rarity baseline: %w", err)
		}
		if baseline.WorkloadCounts[workload] == nil {
			baseline.WorkloadCounts[workload] = map[string]uint64{}
		}
		baseline.WorkloadCounts[workload][signalName] = count
	}
	if err := rows.Err(); err != nil {
		return rarity.Baseline{}, fmt.Errorf("iterate rarity baseline: %w", err)
	}
	return baseline, nil
}
