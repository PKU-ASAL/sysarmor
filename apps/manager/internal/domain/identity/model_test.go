package identity

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestHealthCloneDoesNotShareDocument(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	original := Health{TenantID: tenantID, AgentID: "agent-a", Document: []byte(`{"status":"ok"}`)}
	clone := original.Clone()
	clone.Document[0] = '{'
	if string(original.Document) != `{"status":"ok"}` {
		t.Fatalf("Clone() mutated source document: %s", original.Document)
	}
}

func TestRarityCountFallsBackToGlobal(t *testing.T) {
	baseline := RarityBaseline{WorkloadCounts: map[string]map[string]uint64{
		"global": {"signal-a": 3},
	}}
	if got := baseline.Count("host:a", "signal-a"); got != 3 {
		t.Fatalf("Count() = %d, want 3", got)
	}
}
