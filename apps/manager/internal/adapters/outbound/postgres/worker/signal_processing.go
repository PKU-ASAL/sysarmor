package worker

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func insertCorrelatedSignals(ctx context.Context, tx *sql.Tx, value ports.SignalProcessingBatch) (uint64, error) {
	var inserted uint64
	for _, signal := range value.Signals {
		if strings.TrimSpace(signal.SignalID) == "" || strings.TrimSpace(signal.SubjectID) == "" || strings.TrimSpace(signal.TriggerEventID) == "" {
			return 0, fmt.Errorf("complete correlated Signal identity is required")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO worker_signal_processing (tenant_id,signal_id,agent_id,batch_id,subject_id,trigger_event_id,event_sequence,status) VALUES ($1,$2,$3,$4,$5,$6,$7,'correlated') ON CONFLICT (tenant_id,signal_id) DO NOTHING`,
			value.TenantID, signal.SignalID, value.AgentID, value.BatchID, signal.SubjectID, signal.TriggerEventID, signal.EventSequence)
		if err != nil {
			return 0, fmt.Errorf("store correlated Signal %q: %w", signal.SignalID, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		inserted += uint64(rows)
	}
	return inserted, nil
}

func (repo *TelemetryBatches) CorrelateSignals(ctx context.Context, value ports.SignalProcessingBatch) error {
	if repo == nil || repo.db == nil || strings.TrimSpace(value.TenantID) == "" || strings.TrimSpace(value.AgentID) == "" || strings.TrimSpace(value.BatchID) == "" || strings.TrimSpace(value.ClaimToken) == "" {
		return fmt.Errorf("database and complete Signal processing batch identity are required")
	}
	tx, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Signal correlation: %w", err)
	}
	defer tx.Rollback()
	delta := ports.TelemetryBatchDelta{TenantID: value.TenantID, BatchID: value.BatchID, ClaimToken: value.ClaimToken}
	if err := lockBatch(ctx, tx, delta); err != nil {
		return err
	}
	inserted, err := insertCorrelatedSignals(ctx, tx, value)
	if err != nil {
		return err
	}
	delta.Metrics.ModelCandidatesCorrelated = inserted
	if err := mergeMetrics(ctx, tx, delta); err != nil {
		return err
	}
	return tx.Commit()
}

func insertRejectedSignals(ctx context.Context, tx *sql.Tx, value ports.CandidateRejection) (uint64, error) {
	var inserted uint64
	for _, signal := range value.Signals {
		if strings.TrimSpace(signal.SignalID) == "" {
			return 0, fmt.Errorf("rejected Signal identity is required")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO worker_signal_processing (tenant_id,signal_id,agent_id,batch_id,event_sequence,status,failure_class) VALUES ($1,$2,$3,$4,$5,'reference_rejected',$6) ON CONFLICT (tenant_id,signal_id) DO NOTHING`, value.TenantID, signal.SignalID, value.AgentID, value.BatchID, signal.EventSequence, value.FailureClass)
		if err != nil {
			return 0, fmt.Errorf("store rejected Signal %q: %w", signal.SignalID, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		inserted += uint64(rows)
	}
	return inserted, nil
}

func projectSignals(ctx context.Context, tx *sql.Tx, tenantID, batchID string, signals []ports.SignalProcessingRecord) (uint64, error) {
	var projected uint64
	for _, signal := range signals {
		result, err := tx.ExecContext(ctx, `UPDATE worker_signal_processing SET status='projected',updated_at=$5 WHERE tenant_id=$1 AND signal_id=$2 AND batch_id=$3 AND status='correlated' AND subject_id=$4`, tenantID, signal.SignalID, batchID, signal.SubjectID, time.Now().UTC())
		if err != nil {
			return 0, fmt.Errorf("project Signal %q: %w", signal.SignalID, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rows == 1 {
			projected++
			continue
		}
		if err := requireProjectedSignal(ctx, tx, tenantID, batchID, signal); err != nil {
			return 0, err
		}
	}
	return projected, nil
}

func requireProjectedSignal(ctx context.Context, tx *sql.Tx, tenantID, batchID string, signal ports.SignalProcessingRecord) error {
	var storedBatch, subjectID, eventID, status string
	var sequence uint64
	err := tx.QueryRowContext(ctx, `SELECT batch_id,subject_id,trigger_event_id,event_sequence,status FROM worker_signal_processing WHERE tenant_id=$1 AND signal_id=$2`, tenantID, signal.SignalID).Scan(&storedBatch, &subjectID, &eventID, &sequence, &status)
	if err != nil {
		return fmt.Errorf("read Signal %q projection state: %w", signal.SignalID, err)
	}
	if status != "projected" || storedBatch != batchID || subjectID != signal.SubjectID || eventID != signal.TriggerEventID || sequence != signal.EventSequence {
		return fmt.Errorf("Signal %q projection identity conflicts with correlated state", signal.SignalID)
	}
	return nil
}
