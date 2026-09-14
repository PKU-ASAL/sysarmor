package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestIncompleteTailHandlingDoesNotSwallowReadFailure(t *testing.T) {
	cause := errors.New("read failure")
	if _, err := handleIncompleteTail(nil, 0, tailIgnore, nil, cause); !errors.Is(err, cause) {
		t.Fatalf("tailIgnore error = %v, want %v", err, cause)
	}
}

func TestSegmentAppendRotateAndReadRoundTrip(t *testing.T) {
	root := t.TempDir()
	store, err := Open(t.Context(), Options{RootDir: root, SegmentSize: 180})
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if _, err := store.AppendBatch(t.Context(), testBatch(sequence)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Seal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := filepath.Glob(filepath.Join(root, "spool", "*.seg"))
	if err != nil || len(files) < 2 {
		t.Fatalf("segments=%v err=%v", files, err)
	}
	store = openStore(t, root)
	defer store.Close()
	batches, err := store.ReadBatches(t.Context(), ReadOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 || batches[0].Batch.GetHeader().GetBatchId() != "batch-1" || batches[2].Batch.GetHeader().GetBatchId() != "batch-3" {
		t.Fatalf("batches=%+v", batches)
	}
}

func TestRecoveryTruncatesIncompleteTail(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	if _, err := store.AppendBatch(t.Context(), testBatch(1)); err != nil {
		t.Fatal(err)
	}
	openFiles, _ := filepath.Glob(filepath.Join(root, "spool", "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf("open files=%v", openFiles)
	}
	before, _ := os.Stat(openFiles[0])
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(openFiles[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0, 0, 0, 100, 1, 2, 3})
	_ = f.Close()
	store = openStore(t, root)
	defer store.Close()
	after, _ := os.Stat(openFiles[0])
	if after.Size() != before.Size() {
		t.Fatalf("recovered size=%d want=%d", after.Size(), before.Size())
	}
	batches, err := store.ReadBatches(t.Context(), ReadOptions{Limit: 10})
	if err != nil || len(batches) != 1 {
		t.Fatalf("batches=%d err=%v", len(batches), err)
	}
}

func TestReadBatchesToleratesIncompleteOpenSegmentTail(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.AppendBatch(t.Context(), testBatch(1)); err != nil {
		t.Fatal(err)
	}
	openFiles, err := filepath.Glob(filepath.Join(root, "spool", "*.open"))
	if err != nil || len(openFiles) != 1 {
		t.Fatalf("open files=%v err=%v", openFiles, err)
	}
	file, err := os.OpenFile(openFiles[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0, 100, 1, 2, 3}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(openFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	batches, err := store.ReadBatches(t.Context(), ReadOptions{Limit: 10})
	if err != nil || len(batches) != 1 || batches[0].Batch.GetHeader().GetBatchId() != "batch-1" {
		t.Fatalf("batches=%v err=%v", batches, err)
	}
	after, err := os.Stat(openFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("live read changed open segment size from %d to %d", before.Size(), after.Size())
	}
}

func TestRecoveryContinuesExistingOpenSegment(t *testing.T) {
	root := t.TempDir()
	store := openStore(t, root)
	if _, err := store.AppendBatch(t.Context(), testBatch(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, root)
	if _, err := store.AppendBatch(t.Context(), testBatch(2)); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	openFiles, _ := filepath.Glob(filepath.Join(root, "spool", "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf("open files=%v", openFiles)
	}
	batches, err := store.ReadBatches(t.Context(), ReadOptions{Limit: 10})
	if err != nil || len(batches) != 2 {
		t.Fatalf("batches=%d err=%v", len(batches), err)
	}
}

func testBatch(sequence uint64) *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{SchemaVersion: "v1", Header: &dataplanev1.BatchHeader{BatchId: "batch-" + string(rune('0'+sequence)), EventSeqStart: sequence, EventSeqEnd: sequence}}
}
