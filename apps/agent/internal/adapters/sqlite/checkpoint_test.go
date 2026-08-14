package sqlite

import "testing"

func TestCheckpointSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	want := Checkpoint{SegmentID: 7, RecordOffset: 1234, LastBatchID: "batch-9"}
	if err := store.SaveCheckpoint(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, root)
	defer store.Close()
	got, err := store.Checkpoint(t.Context())
	if err != nil || got.SegmentID != want.SegmentID || got.RecordOffset != want.RecordOffset || got.LastBatchID != want.LastBatchID {
		t.Fatalf("checkpoint=%+v err=%v", got, err)
	}
}
