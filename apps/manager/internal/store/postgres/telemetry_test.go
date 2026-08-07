package postgres

import (
	"context"
	"database/sql/driver"
	"testing"
)

func TestLoadMetricsForTenant(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryResult([][]byte{[]byte(`{"events_ingested":7}`)}, nil)

	metrics, err := (&tableBackend{db: db}).LoadMetricsForTenant(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.EventsIngested != 7 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestLoadRarityForTenant(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryValues([][]driver.Value{{"global", "tenant-signal", int64(4)}}, nil)

	baseline, err := (&tableBackend{db: db}).LoadRarityForTenant(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := baseline.Count("", "tenant-signal"); got != 4 {
		t.Fatalf("rarity count = %d, want 4", got)
	}
}
