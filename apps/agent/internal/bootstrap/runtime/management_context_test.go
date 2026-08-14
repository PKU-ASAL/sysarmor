package runtime

import (
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func TestManagementRuntimeAdaptersUseProjectedIdentity(t *testing.T) {
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
	runner.wireComponents()
	runner.managementState.setRuntimeIdentity(runtimeIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"})

	policyRuntimes := []interface {
		PolicyIdentity() agentcontrol.PolicyIdentity
	}{
		newEndpointPolicyApplication(&runner.policyState, nil, nil),
		newCollectionPolicyApplication(&runner.policyState, nil),
		newDetectionPolicyApplication(&runner.policyState),
		newTelemetryPolicyApplication(&runner.policyState, nil),
		newPolicyProjectionRuntime(&runner.policyState),
	}
	for _, runtime := range policyRuntimes {
		if identity := runtime.PolicyIdentity(); identity.TenantID != "tenant-a" || identity.AgentID != "agent-a" {
			t.Fatalf("policy identity=%+v", identity)
		}
	}
	status := &localStatusService{health: runner.healthRuntime()}
	capability, err := status.Capability(t.Context(), &controlplanev1.CapabilityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if capability.GetTenantId() != "tenant-a" || capability.GetAgentId() != "agent-a" || capability.GetHostId() != "host-a" {
		t.Fatalf("capability identity=%+v", capability)
	}
}

func TestManagedRestartLoadsPolicyWithProjectedIdentity(t *testing.T) {
	store := coordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.managementState.reconcileManagementContext(enrollment); err != nil {
		t.Fatal(err)
	}

	_, policy, _, err := runner.policyState.loadStartupPolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if policy.TenantID != "tenant-a" {
		t.Fatalf("startup policy tenant=%q", policy.TenantID)
	}
}

func TestReconcileManagementContextUsesEnrollmentIdentityWhileEnrolling(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.managementState.reconcileManagementContext(sqlite.Enrollment{
		State: sqlite.StateEnrolling, AgentID: "agent-a", TenantID: "tenant-a",
	})

	identity := runner.managementState.currentIdentity()
	if err != nil || identity.AgentID != "agent-a" || identity.TenantID != "tenant-a" || identity.HostID != "host-a" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
}

func TestReconcileManagementContextRestoresStandaloneIdentity(t *testing.T) {
	runner := managementContextTestRuntime()
	runner.managementState.setRuntimeIdentity(runtimeIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"})

	err := runner.managementState.reconcileManagementContext(sqlite.Enrollment{State: sqlite.StateStandalone})

	identity := runner.managementState.currentIdentity()
	if err != nil || identity.AgentID != "device-a" || identity.TenantID != "local" || identity.HostID != "host-a" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
}

func TestReconcileManagementContextRejectsIncompleteEnrollmentIdentity(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.managementState.reconcileManagementContext(sqlite.Enrollment{State: sqlite.StateEnrolling, AgentID: "agent-a"})

	if err == nil || !strings.Contains(err.Error(), "enrollment identity is incomplete") {
		t.Fatalf("error=%v", err)
	}
	if identity := runner.managementState.currentIdentity(); identity.AgentID != "device-a" || identity.TenantID != "local" {
		t.Fatalf("identity changed after rejected context: %+v", identity)
	}
}

func TestReconcileManagementContextRejectsUnknownState(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.managementState.reconcileManagementContext(sqlite.Enrollment{State: management.State("corrupt")})

	if err == nil || !strings.Contains(err.Error(), "unsupported management state") {
		t.Fatalf("error=%v", err)
	}
}

func managementContextTestRuntime() *Coordinator {
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
	runner.wireComponents()
	runner.managementState.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})
	return runner
}
