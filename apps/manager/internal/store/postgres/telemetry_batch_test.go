package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestClaimTelemetryBatchReturnsDuplicateForCompleted(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryValues([][]driver.Value{{"completed", time.Now().Add(time.Hour)}}, nil)
	claim, err := (&tableBackend{db: db}).ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Now().Add(time.Minute))
	if err != nil || claim != store.BatchDuplicate {
		t.Fatalf("claim = %v, err = %v", claim, err)
	}
}

func TestClaimTelemetryBatchReturnsBusyForLiveLease(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryValues([][]driver.Value{{"processing", time.Now().Add(time.Hour)}}, nil)
	claim, err := (&tableBackend{db: db}).ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Now().Add(time.Minute))
	if err != nil || claim != store.BatchBusy {
		t.Fatalf("claim = %v, err = %v", claim, err)
	}
}

func TestCommitTelemetryBatchCommitsMetricsRarityAndCompletion(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryResultSets([][][]driver.Value{
		{{"processing"}},
		{{[]byte(`{"data_batches_appended":2,"events_ingested":4}`)}},
	})
	err := (&tableBackend{db: db}).CommitTelemetryBatch(context.Background(), store.TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a",
		Metrics: store.Metrics{DataBatchesAppended: 1, EventsIngested: 3},
		Rarity:  rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"signal-a": 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := FakeAllQueries()
	for _, want := range []string{"FOR UPDATE", "INSERT INTO metrics", "INSERT INTO rarity_baseline", "signal_count = rarity_baseline.signal_count + EXCLUDED.signal_count", "status = 'completed'"} {
		if !strings.Contains(queries, want) {
			t.Fatalf("queries missing %q:\n%s", want, queries)
		}
	}
	commits, _ := FakeTransactionCounts()
	if commits != 1 {
		t.Fatalf("commits = %d, want 1", commits)
	}
}

func TestCommitTelemetryBatchRollsBackOnRarityFailure(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryResultSets([][][]driver.Value{{{"processing"}}, {{[]byte(`{}`)}}})
	FakeSetExecErrorForQuery("INSERT INTO rarity_baseline", errors.New("rarity failed"))
	err := (&tableBackend{db: db}).CommitTelemetryBatch(context.Background(), store.TelemetryBatchDelta{
		TenantID: "tenant-a", BatchID: "batch-a",
		Rarity: rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"signal-a": 1}}},
	})
	if err == nil {
		t.Fatal("commit error = nil")
	}
	commits, rollbacks := FakeTransactionCounts()
	if commits != 0 || rollbacks == 0 {
		t.Fatalf("commits=%d rollbacks=%d", commits, rollbacks)
	}
}

func TestLoadRarityForTenantPreservesGlobalFallback(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryValues([][]driver.Value{{"global", "signal-a", int64(4)}}, nil)
	baseline, err := (&tableBackend{db: db}).LoadRarityForTenant(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := baseline.Count("unseen-workload", "signal-a"); got != 4 {
		t.Fatalf("fallback count = %d, want 4", got)
	}
}
