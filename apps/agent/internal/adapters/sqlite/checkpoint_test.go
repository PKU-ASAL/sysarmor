package sqlite

import "testing"

func TestCheckpointSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	want := Checkpoint{SegmentID: 7, RecordOffset: 1234, LastBatchID: "batch-9"}
	if err := store.SaveCheckpoint(t.Context(), "enroll-a", want); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, root)
	defer store.Close()
	got, err := store.Checkpoint(t.Context(), "enroll-a")
	if err != nil || got.SegmentID != want.SegmentID || got.RecordOffset != want.RecordOffset || got.LastBatchID != want.LastBatchID {
		t.Fatalf("checkpoint=%+v err=%v", got, err)
	}
}

func TestCheckpointsAreIsolatedByEnrollmentEpoch(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	if err := store.SaveCheckpoint(t.Context(), "enroll-a", Checkpoint{SegmentID: 1, RecordOffset: 10}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCheckpoint(t.Context(), "enroll-b", Checkpoint{SegmentID: 2, RecordOffset: 20}); err != nil {
		t.Fatal(err)
	}
	a, err := store.Checkpoint(t.Context(), "enroll-a")
	if err != nil || a.SegmentID != 1 || a.RecordOffset != 10 {
		t.Fatalf("enroll-a checkpoint=%+v err=%v", a, err)
	}
	b, err := store.Checkpoint(t.Context(), "enroll-b")
	if err != nil || b.SegmentID != 2 || b.RecordOffset != 20 {
		t.Fatalf("enroll-b checkpoint=%+v err=%v", b, err)
	}
}
