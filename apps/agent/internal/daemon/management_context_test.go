package daemon

import (
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/management"
)

func TestReconcileManagementContextUsesEnrollmentIdentityWhileEnrolling(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.reconcileManagementContext(localstore.Enrollment{
		State: localstore.StateEnrolling, AgentID: "agent-a", TenantID: "tenant-a",
	})

	identity := runner.currentIdentity()
	if err != nil || identity.AgentID != "agent-a" || identity.TenantID != "tenant-a" || identity.HostID != "host-a" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
}

func TestReconcileManagementContextRestoresStandaloneIdentity(t *testing.T) {
	runner := managementContextTestRuntime()
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"})

	err := runner.reconcileManagementContext(localstore.Enrollment{State: localstore.StateStandalone})

	identity := runner.currentIdentity()
	if err != nil || identity.AgentID != "device-a" || identity.TenantID != "local" || identity.HostID != "host-a" {
		t.Fatalf("identity=%+v error=%v", identity, err)
	}
}

func TestReconcileManagementContextRejectsIncompleteEnrollmentIdentity(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.reconcileManagementContext(localstore.Enrollment{State: localstore.StateEnrolling, AgentID: "agent-a"})

	if err == nil || !strings.Contains(err.Error(), "enrollment identity is incomplete") {
		t.Fatalf("error=%v", err)
	}
	if identity := runner.currentIdentity(); identity.AgentID != "device-a" || identity.TenantID != "local" {
		t.Fatalf("identity changed after rejected context: %+v", identity)
	}
}

func TestReconcileManagementContextRejectsUnknownState(t *testing.T) {
	runner := managementContextTestRuntime()

	err := runner.reconcileManagementContext(localstore.Enrollment{State: management.State("corrupt")})

	if err == nil || !strings.Contains(err.Error(), "unsupported management state") {
		t.Fatalf("error=%v", err)
	}
}

func managementContextTestRuntime() *AgentRuntime {
	runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})
	return runner
}
