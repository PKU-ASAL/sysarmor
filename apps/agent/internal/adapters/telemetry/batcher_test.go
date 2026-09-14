package telemetry

import (
	"testing"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
)

func TestBatcherFlushesAtDomainCountDecision(t *testing.T) {
	batcher := NewBatcher(nil, 2, time.Hour, 1)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})
	batcher.Add(&dataplanev1.DataBatch{Signals: []*dataplanev1.SignalFrame{{Sequence: 1}}})

	batch := <-batcher.Batches()
	if len(batch.GetEvents()) != 1 || len(batch.GetSignals()) != 1 || batcher.Stats().FlushedByCount != 1 {
		t.Fatalf("batch=%+v stats=%+v", batch, batcher.Stats())
	}
}

func TestBatcherReconfigureFlushesPendingAndFinalizesBatch(t *testing.T) {
	batcher := NewBatcher(nil, 10, time.Hour, 2, 256<<10)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 7}}})
	batcher.Reconfigure(BatchSettings{MaxItems: 2, MaxBytes: 128 << 10, FlushInterval: time.Second})

	batch := <-batcher.Batches()
	if batch.GetSchemaVersion() != schema.DataPlaneCurrent || batch.GetHeader().GetEventCount() != 1 || batch.GetHeader().GetEventSeqStart() != 7 {
		t.Fatalf("batch=%+v", batch)
	}
	if stats := batcher.Stats(); stats.MaxBytes != 128<<10 || stats.LastFlushReason != "policy" {
		t.Fatalf("stats=%+v", stats)
	}
}
