package runtime

import (
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func TestStandaloneTelemetryFailsClosedWithoutStore(t *testing.T) {
	runner := &Runtime{Config: config.Config{
		Agent: config.AgentConfig{ID: "agent-a", TenantID: "tenant-a"}, Telemetry: config.DefaultTelemetryConfig(),
	}}
	runner.setEndpointPolicy(policymodel.EndpointPolicy{PolicyID: "endpoint-a", Version: 7})
	controller := newApplicationPolicyController(runner, nil, nil)

	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		Context:    agentcontrol.RequestContext{TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "telemetry", Source: agentcontrol.PolicySourceStandalone,
		Telemetry: &agentcontrol.TelemetryPolicy{MaxBatchItems: 64, MaxBatchBytes: 128 << 10, FlushInterval: "2s"},
	})

	if result.Status != "rejected" || !strings.Contains(result.Message, "local store is unavailable") {
		t.Fatalf("result=%+v", result)
	}
	if endpoint := runner.currentEndpointPolicy(); endpoint.PolicyID != "endpoint-a" || endpoint.Version != 7 {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	if effective := runner.currentEffectiveTelemetry(); effective.MaxBatchItems != 0 {
		t.Fatalf("effective=%+v", effective)
	}
}
