package sqlite

import (
	"testing"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestSequenceCursorReturnsPersistedMaxima(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	batch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "batch-range", EventSeqStart: 40, EventSeqEnd: 41,
	}}
	if _, err := store.AppendBatch(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendSignals(t.Context(), []*dataplanev1.SignalFrame{
		signalFrame(17, "2026-07-24T00:00:00Z", "s17", "r1", "high"),
	}); err != nil {
		t.Fatal(err)
	}
	crashBatch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "signal-before-index", SignalSeqStart: 23, SignalSeqEnd: 23,
	}}
	if _, err := store.AppendBatch(t.Context(), crashBatch); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.SequenceCursor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Event != 41 || cursor.Signal != 23 {
		t.Fatalf("cursor=%+v, want event=41 signal=23", cursor)
	}
	stats, err := store.Stats(t.Context())
	if err != nil || stats.LatestEventSequence != 41 {
		t.Fatalf("stats=%+v err=%v, want latest event 41", stats, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, root)
	defer store.Close()
	cursor, err = store.SequenceCursor(t.Context())
	if err != nil || cursor.Event != 41 || cursor.Signal != 23 {
		t.Fatalf("reopened cursor=%+v err=%v, want event=41 signal=23", cursor, err)
	}
}

func TestSequenceCursorSurvivesCapacityDeletion(t *testing.T) {
	root := t.TempDir()
	store, err := Open(t.Context(), Options{RootDir: root, MaxBytes: 1, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	batch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "high-water", EventSeqStart: 40, EventSeqEnd: 41, SignalSeqStart: 22, SignalSeqEnd: 23,
	}}
	if _, err := store.AppendBatch(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := store.EnforceCapacity(t.Context())
	if err != nil || len(result.RemovedSegments) == 0 {
		t.Fatalf("capacity result=%+v err=%v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, root)
	defer store.Close()
	cursor, err := store.SequenceCursor(t.Context())
	if err != nil || cursor.Event != 41 || cursor.Signal != 23 {
		t.Fatalf("cursor=%+v err=%v, want event=41 signal=23", cursor, err)
	}
}
