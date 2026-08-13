package daemon

import (
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
)

func newApplicationPolicyController(runner *AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(
		newPolicyProjectionRuntime(runner),
		agentcontrol.PolicyUseCases{
			StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, runtime, batcher)),
			ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, runtime, nil)),
			Collection:         agentcontrol.NewCollectionPolicyController(newCollectionPolicyApplication(runner, runtime)),
			Detection:          agentcontrol.NewDetectionPolicyController(newDetectionPolicyApplication(runner)),
			Telemetry:          agentcontrol.NewTelemetryPolicyController(newTelemetryPolicyApplication(runner, batcher)),
		},
	)
}
