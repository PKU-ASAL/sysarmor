package daemon

import (
	"context"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type responseRuntime struct {
	runner *AgentRuntime
}

func newResponseRuntime(runner *AgentRuntime) *responseRuntime {
	return &responseRuntime{runner: runner}
}

func (r *responseRuntime) ResponseIdentity() agentcontrol.ResponseIdentity {
	return agentcontrol.ResponseIdentity{
		TenantID: r.runner.Config.Agent.TenantID,
		AgentID:  r.runner.Config.Agent.ID,
	}
}

func (r *responseRuntime) EnforceResponse(ctx context.Context, command contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return r.runner.Sensor.Enforce(ctx, command)
}
