package sqlite

import (
	"fmt"
	"testing"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
)

func BenchmarkAppendBatch1000EPS(b *testing.B) {
	store, err := Open(b.Context(), Options{RootDir: b.TempDir(), MaxBytes: 10 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	b.ReportMetric(0, "events/s")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := benchmarkBatch(uint64(i+1), 100)
		if _, err := store.AppendBatch(b.Context(), batch); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N*100)/b.Elapsed().Seconds(), "events/s")
}

func benchmarkBatch(sequence uint64, eventCount int) *dataplanev1.DataBatch {
	batch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{BatchId: fmt.Sprintf("bench-%d", sequence), EventSeqStart: sequence * uint64(eventCount)}}
	for i := 0; i < eventCount; i++ {
		seq := sequence*uint64(eventCount) + uint64(i)
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{Sequence: seq, Event: &eventv1.CanonicalEvent{Id: fmt.Sprintf("event-%d", seq), Seq: seq, Behavior: "process.exec"}})
	}
	return batch
}
