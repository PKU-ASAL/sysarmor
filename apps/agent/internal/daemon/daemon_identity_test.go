package daemon

import (
	"testing"
	"time"

	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestAgentRuntimeSwitchesBatchIdentityAfterEnrollment(t *testing.T) {
	runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})
	builder := telemetryadapter.NewBatchBuilder(runner, 0)
	runner.telemetryBatcher = telemetryadapter.NewBatcher(builder.NewBatch, 10, time.Hour, 2)
	runner.telemetryBatcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})

	if err := runner.reconcileManagementContext(localstore.Enrollment{State: localstore.StateManaged, AgentID: "agent-a", TenantID: "tenant-a"}); err != nil {
		t.Fatal(err)
	}
	boundary := <-runner.telemetryBatcher.Batches()
	if boundary.GetHeader().GetAgentId() != "device-a" || boundary.GetHeader().GetTenantId() != "local" {
		t.Fatalf("boundary batch identity = %+v", boundary.GetHeader())
	}
	managed := builder.NewBatch(time.Now())
	if managed.GetHeader().GetAgentId() != "agent-a" || managed.GetHeader().GetTenantId() != "tenant-a" {
		t.Fatalf("managed batch identity = %+v", managed.GetHeader())
	}
	managedContext := &controlplanev1.RequestContext{AgentId: "agent-a", TenantId: "tenant-a"}
	if err := runner.validateControlContext(managedContext); err != nil {
		t.Fatalf("managed control context rejected: %v", err)
	}
	ack := runner.bindControlAckIdentity(&controlplanev1.ControlAck{AgentId: "device-a", TenantId: "local"})
	if ack.GetAgentId() != "agent-a" || ack.GetTenantId() != "tenant-a" {
		t.Fatalf("managed ack identity = %+v", ack)
	}

	if err := runner.reconcileManagementContext(localstore.Enrollment{State: localstore.StateStandalone}); err != nil {
		t.Fatal(err)
	}
	standalone := builder.NewBatch(time.Now())
	if standalone.GetHeader().GetAgentId() != "device-a" || standalone.GetHeader().GetTenantId() != "local" {
		t.Fatalf("standalone batch identity = %+v", standalone.GetHeader())
	}
}

func TestAgentRuntimeKeepsPendingBatchForUnchangedIdentity(t *testing.T) {
	runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})
	builder := telemetryadapter.NewBatchBuilder(runner, 0)
	runner.telemetryBatcher = telemetryadapter.NewBatcher(builder.NewBatch, 10, time.Hour, 2)
	runner.telemetryBatcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})

	runner.applyProjectedIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})

	stats := runner.telemetryBatcher.Stats()
	if stats.PendingEvents != 1 || stats.QueuedBatches != 0 {
		t.Fatalf("batcher stats = %+v, want pending event without flush", stats)
	}
}

func TestManagedSessionUsesEnrollmentIdentityWhilePolicyPending(t *testing.T) {
	sessionIdentity := runtimeIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"}
	health := bindHealthToSession(agenthealth.AgentHealth{
		AgentID: "device-a", HostID: "host-a", TenantID: "local",
		PendingPolicy: agenthealth.PendingPolicyStatus{Status: "pending", Source: "managed"},
	}, sessionIdentity)
	if health.AgentID != "agent-a" || health.TenantID != "tenant-a" || health.HostID != "host-a" {
		t.Fatalf("managed session health identity = %+v", health)
	}
	ack := bindControlAckToSession(&controlplanev1.ControlAck{
		AgentId: "device-a", TenantId: "local", Status: "pending",
	}, sessionIdentity)
	if ack.GetAgentId() != "agent-a" || ack.GetTenantId() != "tenant-a" {
		t.Fatalf("managed session ack identity = %+v", ack)
	}
}
