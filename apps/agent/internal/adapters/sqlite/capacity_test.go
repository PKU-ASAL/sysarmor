package sqlite

import (
	"path/filepath"
	"testing"
)

func TestCapacityDeletesUploadedSealedSegmentsBeforeUnuploaded(t *testing.T) {
	root := t.TempDir()
	store, err := Open(t.Context(), Options{RootDir: root, MaxBytes: 1, MinFreeBytes: 1, SegmentSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := store.AppendBatch(t.Context(), testBatch(sequence)); err != nil {
			t.Fatal(err)
		}
		if err := store.Seal(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AppendBatch(t.Context(), testBatch(4)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCheckpoint(t.Context(), "enroll-a", Checkpoint{SegmentID: 3}); err != nil {
		t.Fatal(err)
	}

	result, err := store.EnforceCapacity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RemovedSegments) < 2 || result.RemovedSegments[0] != 1 || result.RemovedSegments[1] != 2 {
		t.Fatalf("removed=%+v", result.RemovedSegments)
	}
	openFiles, _ := filepath.Glob(filepath.Join(root, "spool", "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf("open files=%v", openFiles)
	}
}
