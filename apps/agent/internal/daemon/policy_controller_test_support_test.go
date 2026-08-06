package daemon

import (
	"context"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
)

type policyController struct {
	runner  *AgentRuntime
	runtime sensorruntime.Runtime
	batcher *telemetry.Batcher
}

func newPolicyController(runner *AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetry.Batcher) *policyController {
	return &policyController{runner: runner, runtime: runtime, batcher: batcher}
}

func (s *policyController) ApplyPolicy(ctx context.Context, command agentcontrol.PolicyCommand) agentcontrol.Result {
	return newApplicationPolicyController(s.runner, s.runtime, s.batcher).ApplyPolicy(ctx, command)
}

func (s *policyController) CurrentPolicy(ctx context.Context) (agentcontrol.PolicySnapshot, error) {
	return newApplicationPolicyController(s.runner, s.runtime, s.batcher).CurrentPolicy(ctx)
}
