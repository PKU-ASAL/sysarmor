package worker

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
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
	if err := repository.Commit(context.Background(), ports.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "shared", ClaimToken: token}); err != nil {
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

func TestTelemetryBatchesCommitMetricsAndRarity(t *testing.T) {
	db := newTelemetryDB(t)
	repository := NewTelemetryBatches(db)
	_, token, _ := repository.Claim(context.Background(), "tenant-a", "batch-a", time.Minute)
	delta := ports.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: token, Metrics: ports.TelemetryMetrics{DataBatches: 1, Events: 2}, Rarity: identity.RarityBaseline{WorkloadCounts: map[string]map[string]uint64{"workload-a": {"signal-a": 3}}}}
	if err := repository.Commit(context.Background(), delta); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM telemetry_batches WHERE tenant_id=? AND batch_id=?`, "tenant-a", "batch-a").Scan(&status); err != nil || status != "completed" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	var count uint64
	if err := db.QueryRow(`SELECT signal_count FROM rarity_baseline WHERE tenant_id=? AND workload_key=? AND signal_name=?`, "tenant-a", "workload-a", "signal-a").Scan(&count); err != nil || count != 3 {
		t.Fatalf("rarity=%d err=%v", count, err)
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
