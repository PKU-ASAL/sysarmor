package telemetry

import (
	"testing"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
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
