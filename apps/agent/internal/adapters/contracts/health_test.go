package contracts

import (
	"testing"

	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
)

func TestAgentHealthMapsDomainSnapshot(t *testing.T) {
	snapshot := domainhealth.Snapshot{
		Runtime: domainhealth.Runtime{
			AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a", ScopeType: "container", ScopeSelector: "c-a",
			PolicyID: "policy-a", PolicyVersion: 7, PolicyMode: "observe",
			PendingPolicy: domainhealth.PendingPolicy{Status: "pending", Source: "managed", PolicyID: "policy-b", Version: 8, Digest: "sha256:a"},
		},
		Status: domainhealth.StatusDegraded,
		Sensor: domainhealth.Sensor{Backend: "fake", Running: true, EventsSeen: 3},
		Telemetry: domainhealth.Telemetry{
			Bus:     domainhealth.Bus{EventCapacity: 16, EventDropped: 2},
			Batcher: domainhealth.Batcher{QueuedBatches: 3}, Sender: domainhealth.Sender{SentBatches: 4},
		},
		Detection: domainhealth.Detection{
			PolicyID: "detection-a", DefaultManifestVersion: "release-v1",
			Learning: domainhealth.Learning{Status: "degraded", LastError: "invalid model bundle"},
			CEP:      domainhealth.CEP{ActiveGroups: 5, Degraded: true},
		},
	}

	got := AgentHealth(snapshot)
	if got.AgentID != "agent-a" || got.Scope.Selector != "c-a" || got.PendingPolicy.Version != 8 {
		t.Fatalf("identity/pending=%+v", got)
	}
	if got.TelemetryBus.EventCapacity != 16 || got.TelemetryBatcher.QueuedBatches != 3 || got.TelemetrySender.SentBatches != 4 {
		t.Fatalf("telemetry=%+v", got)
	}
	if got.Detection.DefaultManifestVersion != "release-v1" || got.CEP.ActiveGroups != 5 || !got.CEP.Degraded {
		t.Fatalf("detection=%+v cep=%+v", got.Detection, got.CEP)
	}
	if got.Detection.Learning.Status != "degraded" || got.Detection.Learning.LastError != "invalid model bundle" {
		t.Fatalf("learning health = %+v", got.Detection.Learning)
	}
}
