package worker

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestTelemetryBatchesClaimsAreTenantScoped(t *testing.T) {
	db := newTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	claim, token, err := repository.Claim(context.Background(), "tenant-a", "shared", time.Minute)
	if err != nil || claim != ports.TelemetryClaimed || token == "" {
		t.Fatalf("first claim=%v token=%q err=%v", claim, token, err)
	}
	if _, err := db.Exec(`UPDATE telemetry_batches SET status='completed' WHERE tenant_id=? AND batch_id=? AND claim_token=?`, "tenant-a", "shared", token); err != nil {
		t.Fatal(err)
	}
	claim, _, err = repository.Claim(context.Background(), "tenant-a", "shared", time.Minute)
	if err != nil || claim != ports.TelemetryDuplicate {
		t.Fatalf("duplicate claim=%v err=%v", claim, err)
	}
	claim, _, err = repository.Claim(context.Background(), "tenant-b", "shared", time.Minute)
	if err != nil || claim != ports.TelemetryClaimed {
		t.Fatalf("other tenant claim=%v err=%v", claim, err)
	}
}

func TestAddMetricsAccumulatesCountersAndLatency(t *testing.T) {
	metrics := metricsDocument{DataBatches: 1, Events: 2, TotalLatency: 10, MaxLatency: 10}
	addMetrics(&metrics, ports.TelemetryMetrics{DataBatches: 1, Events: 3, TotalLatencyMs: 20, MaxLatencyMs: 20, LastLatencyMs: 20})
	if metrics.DataBatches != 2 || metrics.Events != 5 || metrics.TotalLatency != 30 || metrics.MaxLatency != 20 || metrics.LastLatency != 20 || metrics.AverageLatency != 15 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestMetricsReadQueryLocksPostgresRow(t *testing.T) {
	if query := metricsReadQuery(); !strings.Contains(query, "FOR UPDATE") {
		t.Fatalf("metrics read query does not lock PostgreSQL row: %s", query)
	}
}

func TestTelemetryBatchesRejectsSubMillisecondLease(t *testing.T) {
	repository := NewTelemetryBatches(newTelemetryDB(t))
	if _, _, err := repository.Claim(context.Background(), "tenant-a", "batch-a", time.Nanosecond); err == nil {
		t.Fatal("Claim() accepted sub-millisecond lease")
	}
}

func TestTelemetryBatchesTreatsLostLeaseUpdateAsBusy(t *testing.T) {
	db := newTelemetryDB(t)
	_, err := db.Exec(`CREATE TRIGGER ignore_expired_claim BEFORE UPDATE OF claim_token ON telemetry_batches BEGIN SELECT RAISE(IGNORE); END`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telemetry_batches (tenant_id,batch_id,status,claim_token,lease_until) VALUES ('tenant-a','batch-a','processing','old',?)`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	claim, _, err := NewTelemetryBatches(db).Claim(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil || claim != ports.TelemetryBusy {
		t.Fatalf("lost lease claim=%v err=%v, want busy", claim, err)
	}
}

func TestTakeoverExpiredClaimRejectsStaleLeaseSnapshot(t *testing.T) {
	db := newTelemetryDB(t)
	expired := time.Now().UTC().Add(-time.Minute)
	if _, err := db.Exec(`INSERT INTO telemetry_batches (tenant_id,batch_id,status,claim_token,lease_until) VALUES ('tenant-a','batch-a','processing','old',?)`, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE telemetry_batches SET claim_token='racer', lease_until=? WHERE tenant_id='tenant-a' AND batch_id='batch-a'`, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	claimed, err := takeoverExpiredClaim(context.Background(), db, "tenant-a", "batch-a", "new", "old", expired, time.Minute)

	if err != nil || claimed {
		t.Fatalf("claimed=%t err=%v, want stale snapshot rejected", claimed, err)
	}
}

func newTelemetryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE telemetry_batches (tenant_id TEXT, batch_id TEXT, status TEXT, claim_token TEXT, lease_until TIMESTAMP, completed_at TIMESTAMP, PRIMARY KEY (tenant_id,batch_id))`,
		`CREATE TABLE metrics (tenant_id TEXT, metric_key TEXT, data BLOB, PRIMARY KEY (tenant_id,metric_key))`,
		`CREATE TABLE rarity_baseline (tenant_id TEXT, workload_key TEXT, signal_name TEXT, signal_count INTEGER, data BLOB, updated_at TIMESTAMP, PRIMARY KEY (tenant_id,workload_key,signal_name))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
