package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
)

func TestFileTelemetryBatchCommitSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	claim, token, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil || claim != BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	err = st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a",
		ClaimToken: token,
		Metrics:    Metrics{DataBatchesAppended: 1, EventsIngested: 3},
		Rarity:     rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"signal-a": 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	claim, _, err = reopened.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil || claim != BatchDuplicate {
		t.Fatalf("reopened claim=%v err=%v", claim, err)
	}
	if got := reopened.MetricsSnapshotForTenant("tenant-a").EventsIngested; got != 3 {
		t.Fatalf("events=%d, want 3", got)
	}
	if got := reopened.RarityBaselineSnapshotForTenant("tenant-a").Count("new-workload", "signal-a"); got != 2 {
		t.Fatalf("rarity=%d, want 2", got)
	}
}

func TestTelemetryBatchClaimIsTenantScopedAndReclaimsExpiredLease(t *testing.T) {
	st := &Store{}
	if claim, _, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "shared", time.Minute); err != nil || claim != BatchClaimed {
		t.Fatalf("first claim=%v err=%v", claim, err)
	}
	record := st.TelemetryBatches[telemetryBatchKey("tenant-a", "shared")]
	record.LeaseUntil = time.Now().Add(-time.Minute)
	st.TelemetryBatches[telemetryBatchKey("tenant-a", "shared")] = record
	if claim, _, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "shared", time.Minute); err != nil || claim != BatchClaimed {
		t.Fatalf("expired reclaim=%v err=%v", claim, err)
	}
	if claim, _, err := st.ClaimTelemetryBatch(context.Background(), "tenant-b", "shared", time.Minute); err != nil || claim != BatchClaimed {
		t.Fatalf("other tenant claim=%v err=%v", claim, err)
	}
}

func TestTelemetryBatchRejectsSubMillisecondLease(t *testing.T) {
	st := &Store{}
	if _, _, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Nanosecond); err == nil {
		t.Fatal("sub-millisecond lease was accepted")
	}
}

func TestReclaimedTelemetryBatchRejectsStaleClaimToken(t *testing.T) {
	st := &Store{}
	_, staleToken, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	record := st.TelemetryBatches[telemetryBatchKey("tenant-a", "batch-a")]
	record.LeaseUntil = time.Now().Add(-time.Minute)
	st.TelemetryBatches[telemetryBatchKey("tenant-a", "batch-a")] = record
	claim, currentToken, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Minute)
	if err != nil || claim != BatchClaimed {
		t.Fatalf("reclaim=%v err=%v", claim, err)
	}
	if err := st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: staleToken}); err == nil {
		t.Fatal("stale token committed reclaimed batch")
	}
	if err := st.AbandonTelemetryBatch(context.Background(), "tenant-a", "batch-a", staleToken); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: currentToken}); err != nil {
		t.Fatal(err)
	}
}
