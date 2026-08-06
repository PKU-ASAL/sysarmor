package daemon

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
)

func TestStandaloneTelemetryWithoutStoreDoesNotMutateEndpointPolicy(t *testing.T) {
	runner := &AgentRuntime{Config: config.Config{
		Agent: config.AgentConfig{ID: "agent-a", TenantID: "tenant-a"}, Telemetry: config.DefaultTelemetryConfig(),
	}}
	runner.setEndpointPolicy(agentpolicy.EndpointPolicy{PolicyID: "endpoint-a", Version: 7})
	controller := newPolicyController(runner, nil, nil)

	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		Context:    agentcontrol.RequestContext{TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "telemetry", Source: agentcontrol.PolicySourceStandalone,
		Telemetry: &agentcontrol.TelemetryPolicy{MaxBatchItems: 64, MaxBatchBytes: 128 << 10, FlushInterval: "2s"},
	})

	if result.Status != "applied" {
		t.Fatalf("result=%+v", result)
	}
	if endpoint := runner.currentEndpointPolicy(); endpoint.PolicyID != "endpoint-a" || endpoint.Version != 7 {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	if effective := runner.currentEffectiveTelemetry(); effective.MaxBatchItems != 64 || effective.FlushInterval != 2*time.Second {
		t.Fatalf("effective=%+v", effective)
	}
}
