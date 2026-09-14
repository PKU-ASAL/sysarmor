package identity

import (
	"context"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"testing"
)

func TestGatewaySessionStoreRecordsAndDetectsBatch(t *testing.T) {
	db := newIdentityTestDB(t)
	store := NewGatewaySessionStore(db)
	batch := ports.BatchEnvelope{TenantID: "tenant-a", AgentID: "agent-a", HostID: "host-a", BatchID: "batch-a", Transport: "grpc"}
	session, err := store.RecordBatch(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.IsDuplicate(context.Background(), "tenant-a", "agent-a", "batch-a")
	if err != nil || !duplicate || session.Cursor != "batch-a" {
		t.Fatalf("session=%+v duplicate=%t err=%v", session, duplicate, err)
	}
	other, err := store.IsDuplicate(context.Background(), "tenant-b", "agent-a", "batch-a")
	if err != nil || other {
		t.Fatalf("other tenant duplicate=%t err=%v", other, err)
	}
}
