package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestTelemetryBatchesPostgresConcurrentCommitsPreserveMetrics(t *testing.T) {
	db := newPostgresTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	const batches = 16
	deltas := make([]ports.TelemetryBatchDelta, 0, batches)
	for index := 1; index <= batches; index++ {
		batchID := fmt.Sprintf("batch-%02d", index)
		_, token, err := repository.Claim(context.Background(), "tenant-a", batchID, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		deltas = append(deltas, ports.TelemetryBatchDelta{
			TenantID: "tenant-a", BatchID: batchID, ClaimToken: token,
			Metrics: ports.TelemetryMetrics{DataBatches: 1, Events: uint64(index), TotalLatencyMs: uint64(index), MaxLatencyMs: uint64(index), LastLatencyMs: uint64(index)},
		})
	}
	start := make(chan struct{})
	errors := make(chan error, batches)
	var wait sync.WaitGroup
	for _, delta := range deltas {
		wait.Add(1)
		go func(delta ports.TelemetryBatchDelta) {
			defer wait.Done()
			<-start
			errors <- repository.Commit(context.Background(), delta)
		}(delta)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	metrics := readPostgresMetrics(t, db, "tenant-a")
	wantTotal := uint64(batches * (batches + 1) / 2)
	if metrics.DataBatches != batches || metrics.Events != wantTotal || metrics.TotalLatency != wantTotal || metrics.MaxLatency != batches || metrics.AverageLatency != float64(wantTotal)/batches {
		t.Fatalf("metrics = %+v", metrics)
	}
	var completed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM telemetry_batches WHERE tenant_id=$1 AND status='completed'`, "tenant-a").Scan(&completed); err != nil || completed != batches {
		t.Fatalf("completed=%d err=%v", completed, err)
	}
}

func TestTelemetryBatchesPostgresCommitWaitsForMetricsRowLock(t *testing.T) {
	db := newPostgresTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	_, token, err := repository.Claim(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO metrics (tenant_id,metric_key,data) VALUES ($1,'manager',$2)`, "tenant-a", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	locker, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	var raw []byte
	if err := locker.QueryRow(`SELECT data FROM metrics WHERE tenant_id=$1 AND metric_key='manager' FOR UPDATE`, "tenant-a").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	delta := ports.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: token, Metrics: ports.TelemetryMetrics{DataBatches: 1, Events: 2}}
	blockedContext, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := repository.Commit(blockedContext, delta); err == nil || blockedContext.Err() != context.DeadlineExceeded {
		t.Fatalf("Commit() error=%v context=%v, want lock timeout", err, blockedContext.Err())
	}
	if err := locker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := repository.Commit(context.Background(), delta); err != nil {
		t.Fatal(err)
	}
	if metrics := readPostgresMetrics(t, db, "tenant-a"); metrics.DataBatches != 1 || metrics.Events != 2 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestTelemetryBatchesPostgresCandidateRejectionsAreIdempotent(t *testing.T) {
	db := newPostgresTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	sequence := uint64(7)
	value := ports.CandidateRejection{TenantID: "tenant-a", AgentID: "agent-a", BatchID: "batch-a", Signals: []ports.RejectedSignal{{SignalID: "signal-a", EventSequence: &sequence}, {SignalID: "signal-b"}}, FailureClass: "missing_current_candidate_event"}
	for range 2 {
		if err := repository.RecordCandidateRejection(context.Background(), value); err != nil {
			t.Fatal(err)
		}
	}
	if metrics := readPostgresMetrics(t, db, "tenant-a"); metrics.ModelCandidatesReferenceRejected != 2 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestTelemetryBatchesPostgresSignalLifecycleIsIdempotent(t *testing.T) {
	db := newPostgresTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	_, token, err := repository.Claim(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signal := ports.SignalProcessingRecord{
		SignalID: "signal-a", SubjectID: "process-a",
		TriggerEventID: "event-a", EventSequence: 7,
	}
	batch := ports.SignalProcessingBatch{
		TenantID: "tenant-a", AgentID: "agent-a", BatchID: "batch-a",
		ClaimToken: token, Signals: []ports.SignalProcessingRecord{signal},
	}
	for range 2 {
		if err := repository.CorrelateSignals(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.Commit(context.Background(), ports.TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: token,
		ProjectedSignals: []ports.SignalProcessingRecord{signal},
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM worker_signal_processing WHERE tenant_id=$1 AND signal_id=$2`, "tenant-a", "signal-a").Scan(&status); err != nil || status != "projected" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	metrics := readPostgresMetrics(t, db, "tenant-a")
	if metrics.ModelCandidatesCorrelated != 1 || metrics.ModelCandidatesProjected != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestTelemetryBatchesPostgresProjectionFailurePreservesCorrelatedState(t *testing.T) {
	db := newPostgresTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	_, token, err := repository.Claim(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signal := ports.SignalProcessingRecord{
		SignalID: "signal-a", SubjectID: "process-a",
		TriggerEventID: "event-a", EventSequence: 7,
	}
	if err := repository.CorrelateSignals(context.Background(), ports.SignalProcessingBatch{
		TenantID: "tenant-a", AgentID: "agent-a", BatchID: "batch-a",
		ClaimToken: token, Signals: []ports.SignalProcessingRecord{signal},
	}); err != nil {
		t.Fatal(err)
	}
	conflicting := signal
	conflicting.SubjectID = "other-process"
	err = repository.Commit(context.Background(), ports.TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: token,
		ProjectedSignals: []ports.SignalProcessingRecord{conflicting},
	})
	if err == nil {
		t.Fatal("Commit() succeeded with conflicting Signal identity")
	}
	var status string
	if queryErr := db.QueryRow(`SELECT status FROM worker_signal_processing WHERE tenant_id=$1 AND signal_id=$2`, "tenant-a", "signal-a").Scan(&status); queryErr != nil || status != "correlated" {
		t.Fatalf("status=%q err=%v", status, queryErr)
	}
	metrics := readPostgresMetrics(t, db, "tenant-a")
	if metrics.ModelCandidatesCorrelated != 1 || metrics.ModelCandidatesProjected != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func newPostgresTelemetryDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SYSARMOR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SYSARMOR_TEST_POSTGRES_DSN is required for PostgreSQL integration tests")
	}
	schema := fmt.Sprintf("worker_test_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	testDSN, err := postgresDSNWithSchema(dsn, schema)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", testDSN)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(32)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE telemetry_batches (tenant_id TEXT, batch_id TEXT, status TEXT, claim_token TEXT, lease_until TIMESTAMPTZ, completed_at TIMESTAMPTZ, PRIMARY KEY (tenant_id,batch_id))`,
		`CREATE TABLE metrics (tenant_id TEXT, metric_key TEXT, data JSONB NOT NULL, PRIMARY KEY (tenant_id,metric_key))`,
		`CREATE TABLE rarity_baseline (tenant_id TEXT, workload_key TEXT, signal_name TEXT, signal_count BIGINT, data JSONB, updated_at TIMESTAMPTZ, PRIMARY KEY (tenant_id,workload_key,signal_name))`,
		`CREATE TABLE worker_signal_processing (tenant_id TEXT, signal_id TEXT, agent_id TEXT, batch_id TEXT, subject_id TEXT NOT NULL DEFAULT '', trigger_event_id TEXT NOT NULL DEFAULT '', event_sequence BIGINT CHECK (event_sequence >= 0), status TEXT, failure_class TEXT, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY (tenant_id,signal_id))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func postgresDSNWithSchema(dsn, schema string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func readPostgresMetrics(t *testing.T, db *sql.DB, tenantID string) metricsDocument {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT data FROM metrics WHERE tenant_id=$1 AND metric_key='manager'`, tenantID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var metrics metricsDocument
	if err := json.Unmarshal(raw, &metrics); err != nil {
		t.Fatal(err)
	}
	return metrics
}
