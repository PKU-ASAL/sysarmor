package runtime

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func TestRuntimeProjectsCurrentTelemetryContext(t *testing.T) {
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{
		ID: "device-a", HostID: "host-a", TenantID: "local", Labels: map[string]string{"site": "lab"},
	}}}
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"})
	runner.setPolicy(policymodel.Policy{PolicyID: "managed-policy", Version: 7, Mode: "enforcing"})

	context := runner.TelemetryContext()

	if context.AgentID != "agent-a" || context.HostID != "host-a" || context.TenantID != "tenant-a" {
		t.Fatalf("identity context = %+v", context)
	}
	if context.PolicyID != "managed-policy" || context.PolicyVersion != 7 || context.PolicyMode != "enforcing" {
		t.Fatalf("policy context = %+v", context)
	}
	context.Labels["site"] = "changed"
	if runner.Config.Agent.Labels["site"] != "lab" {
		t.Fatalf("runtime labels were modified: %+v", runner.Config.Agent.Labels)
	}
}
