package daemon

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestResponseRuntimeExposesIdentityAndDelegatesEnforcement(t *testing.T) {
	runner := &AgentRuntime{
		Config: config.Config{Agent: config.AgentConfig{TenantID: "local", ID: "device-a"}},
		Sensor: &healthOnlySensor{health: contract.Health{Backend: "fake"}},
	}
	runner.setRuntimeIdentity(runtimeIdentity{TenantID: "tenant-a", AgentID: "agent-a"})
	runtime := newResponseRuntime(runner)
	if identity := runtime.ResponseIdentity(); identity.TenantID != "tenant-a" || identity.AgentID != "agent-a" {
		t.Fatalf("identity=%+v", identity)
	}
	ack, err := runtime.EnforceResponse(t.Context(), contract.EnforcementCmd{ID: "response-a", Action: "kill"})
	if err != nil || !ack.Unsupported || ack.ID != "response-a" {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
}
