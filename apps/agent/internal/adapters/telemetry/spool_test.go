package telemetry

import (
	"path/filepath"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestLocalSpoolRoundTripsStoredBatchAndCheckpoint(t *testing.T) {
	store, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "standalone", EnrollmentEpoch: "standalone", EventSeqStart: 6, TenantId: "local", AgentId: "device-a",
	}}
	if _, err := store.AppendBatch(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	want := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "batch-a", EnrollmentEpoch: "enroll-a", EventSeqStart: 7, TenantId: "tenant-a", AgentId: "agent-a",
	}}
	position, err := store.AppendBatch(t.Context(), want)
	if err != nil {
		t.Fatal(err)
	}
	spool := NewLocalSpool(store)

	batches, err := spool.Read(t.Context(), "enroll-a", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || batches[0].Batch.ID != "batch-a" || batches[0].Batch.TenantID != "tenant-a" {
		t.Fatalf("batches = %+v", batches)
	}
	if err := spool.SaveCheckpoint(t.Context(), "enroll-a", batches[0].Position); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := spool.Checkpoint(t.Context(), "enroll-a")
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.BatchID != "batch-a" || checkpoint.RecordOffset != position.RecordOffset {
		t.Fatalf("checkpoint = %+v", checkpoint)
	}
}
