package daemon

import (
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
)

func newApplicationPolicyController(runner *AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetry.Batcher) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(
		newPolicyProjectionRuntime(runner),
		agentcontrol.PolicyUseCases{
			StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, runtime, batcher)),
			ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, runtime, nil)),
			Collection:         agentcontrol.NewCollectionPolicyController(newCollectionPolicyRuntime(runner, runtime)),
			Detection:          agentcontrol.NewDetectionPolicyController(newDetectionPolicyRuntime(runner)),
			Telemetry:          agentcontrol.NewTelemetryPolicyController(newTelemetryPolicyRuntime(runner, batcher)),
		},
	)
}
