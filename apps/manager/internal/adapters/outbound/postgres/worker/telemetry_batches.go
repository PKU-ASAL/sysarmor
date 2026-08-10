package worker

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type TelemetryBatches struct{ db *sql.DB }

func NewTelemetryBatches(db *sql.DB) *TelemetryBatches { return &TelemetryBatches{db: db} }

func (repo *TelemetryBatches) Claim(ctx context.Context, tenantID, batchID string, lease time.Duration) (ports.TelemetryClaim, string, error) {
	if repo == nil || repo.db == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(batchID) == "" || lease <= 0 {
		return ports.TelemetryBusy, "", fmt.Errorf("database, tenant_id, batch_id, and positive lease are required")
	}
	token, err := claimToken()
	if err != nil {
		return ports.TelemetryBusy, "", err
	}
	tx, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.TelemetryBusy, "", fmt.Errorf("begin telemetry claim: %w", err)
	}
	defer tx.Rollback()
	claim, err := claimBatch(ctx, tx, tenantID, batchID, token, lease)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return ports.TelemetryBusy, "", err
	}
	return claim, token, nil
}

func claimBatch(ctx context.Context, tx *sql.Tx, tenantID, batchID, token string, lease time.Duration) (ports.TelemetryClaim, error) {
	var status string
	var leaseUntil time.Time
	err := tx.QueryRowContext(ctx, `SELECT status, lease_until FROM telemetry_batches WHERE tenant_id=$1 AND batch_id=$2`, tenantID, batchID).Scan(&status, &leaseUntil)
	if err == sql.ErrNoRows {
		_, err = tx.ExecContext(ctx, `INSERT INTO telemetry_batches (tenant_id,batch_id,status,claim_token,lease_until) VALUES ($1,$2,'processing',$3,$4)`, tenantID, batchID, token, time.Now().UTC().Add(lease))
		return ports.TelemetryClaimed, err
	}
	if err != nil {
		return ports.TelemetryBusy, fmt.Errorf("read telemetry claim: %w", err)
	}
	if status == "completed" {
		return ports.TelemetryDuplicate, nil
	}
	if leaseUntil.After(time.Now().UTC()) {
		return ports.TelemetryBusy, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE telemetry_batches SET claim_token=$3, lease_until=$4 WHERE tenant_id=$1 AND batch_id=$2 AND status='processing'`, tenantID, batchID, token, time.Now().UTC().Add(lease))
	return ports.TelemetryClaimed, err
}

func (repo *TelemetryBatches) Commit(ctx context.Context, delta ports.TelemetryBatchDelta) error {
	tx, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin telemetry commit: %w", err)
	}
	defer tx.Rollback()
	if err = lockBatch(ctx, tx, delta); err == nil {
		err = mergeMetrics(ctx, tx, delta)
	}
	if err == nil {
		err = mergeRarity(ctx, tx, delta)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE telemetry_batches SET status='completed', completed_at=$4 WHERE tenant_id=$1 AND batch_id=$2 AND claim_token=$3 AND status='processing'`, delta.TenantID, delta.BatchID, delta.ClaimToken, time.Now().UTC())
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func lockBatch(ctx context.Context, tx *sql.Tx, delta ports.TelemetryBatchDelta) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM telemetry_batches WHERE tenant_id=$1 AND batch_id=$2 AND claim_token=$3`, delta.TenantID, delta.BatchID, delta.ClaimToken).Scan(&status)
	if err != nil {
		return fmt.Errorf("lock telemetry batch: %w", err)
	}
	if status != "processing" {
		return fmt.Errorf("telemetry batch is not processing")
	}
	return nil
}

func (repo *TelemetryBatches) Abandon(ctx context.Context, tenantID, batchID, token string) error {
	_, err := repo.db.ExecContext(ctx, `DELETE FROM telemetry_batches WHERE tenant_id=$1 AND batch_id=$2 AND status='processing' AND claim_token=$3`, tenantID, batchID, token)
	return err
}

type metricsDocument struct {
	DataBatches     uint64  `json:"data_batches_appended"`
	Events          uint64  `json:"events_ingested"`
	EndpointSignals uint64  `json:"endpoint_signals_ingested"`
	CloudSignals    uint64  `json:"cloud_signals_emitted"`
	Signals         uint64  `json:"signals_emitted"`
	Incidents       uint64  `json:"incidents_created"`
	LastLatency     uint64  `json:"last_convergence_latency_ms"`
	MaxLatency      uint64  `json:"max_convergence_latency_ms"`
	TotalLatency    uint64  `json:"total_convergence_latency_ms"`
	AverageLatency  float64 `json:"average_convergence_latency_ms"`
}

func mergeMetrics(ctx context.Context, tx *sql.Tx, delta ports.TelemetryBatchDelta) error {
	current := metricsDocument{}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT data FROM metrics WHERE tenant_id=$1 AND metric_key='manager'`, delta.TenantID).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read tenant metrics: %w", err)
	}
	if err == nil && json.Unmarshal(raw, &current) != nil {
		return fmt.Errorf("decode tenant metrics")
	}
	addMetrics(&current, delta.Metrics)
	raw, _ = json.Marshal(current)
	_, err = tx.ExecContext(ctx, `INSERT INTO metrics (tenant_id,metric_key,data) VALUES ($1,'manager',$2) ON CONFLICT (tenant_id,metric_key) DO UPDATE SET data=EXCLUDED.data`, delta.TenantID, raw)
	return err
}

func addMetrics(value *metricsDocument, delta ports.TelemetryMetrics) {
	value.DataBatches += delta.DataBatches
	value.Events += delta.Events
	value.EndpointSignals += delta.EndpointSignals
	value.CloudSignals += delta.CloudSignals
	value.Signals += delta.Signals
	value.Incidents += delta.Incidents
	value.LastLatency = delta.LastLatencyMs
	value.TotalLatency += delta.TotalLatencyMs
	if delta.MaxLatencyMs > value.MaxLatency {
		value.MaxLatency = delta.MaxLatencyMs
	}
	if value.DataBatches > 0 {
		value.AverageLatency = float64(value.TotalLatency) / float64(value.DataBatches)
	}
}

func mergeRarity(ctx context.Context, tx *sql.Tx, delta ports.TelemetryBatchDelta) error {
	for workload, signals := range delta.Rarity.WorkloadCounts {
		for signal, count := range signals {
			if count == 0 {
				continue
			}
			data, _ := json.Marshal(map[string]any{"workload_key": workload, "signal_name": signal, "signal_count": count})
			_, err := tx.ExecContext(ctx, `INSERT INTO rarity_baseline (tenant_id,workload_key,signal_name,signal_count,data,updated_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,workload_key,signal_name) DO UPDATE SET signal_count=rarity_baseline.signal_count+EXCLUDED.signal_count,data=EXCLUDED.data,updated_at=EXCLUDED.updated_at`, delta.TenantID, workload, signal, count, data, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("increment tenant rarity: %w", err)
			}
		}
	}
	return nil
}

func claimToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate claim token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
