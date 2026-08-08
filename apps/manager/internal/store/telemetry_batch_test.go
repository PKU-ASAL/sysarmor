package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
)

func TestFileTelemetryBatchCommitSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Now().Add(time.Minute))
	if err != nil || claim != BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	err = st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a",
		Metrics: Metrics{DataBatchesAppended: 1, EventsIngested: 3},
		Rarity:  rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"signal-a": 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	claim, err = reopened.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Now().Add(time.Minute))
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
	now := time.Now()
	if claim, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "shared", now.Add(-time.Minute)); err != nil || claim != BatchClaimed {
		t.Fatalf("first claim=%v err=%v", claim, err)
	}
	if claim, err := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "shared", now.Add(time.Minute)); err != nil || claim != BatchClaimed {
		t.Fatalf("expired reclaim=%v err=%v", claim, err)
	}
	if claim, err := st.ClaimTelemetryBatch(context.Background(), "tenant-b", "shared", now.Add(time.Minute)); err != nil || claim != BatchClaimed {
		t.Fatalf("other tenant claim=%v err=%v", claim, err)
	}
}
