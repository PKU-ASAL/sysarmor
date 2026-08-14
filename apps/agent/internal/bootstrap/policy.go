package bootstrap

import (
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	agentruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/bootstrap/runtime"
)

func newPolicyController(runner *agentruntime.Coordinator, runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(
		agentruntime.NewPolicyProjectionRuntime(runner),
		agentcontrol.PolicyUseCases{
			StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(agentruntime.NewEndpointPolicyApplication(runner, runtime, batcher)),
			ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(agentruntime.NewEndpointPolicyApplication(runner, runtime, nil)),
			Collection:         agentcontrol.NewCollectionPolicyController(agentruntime.NewCollectionPolicyApplication(runner, runtime)),
			Detection:          agentcontrol.NewDetectionPolicyController(agentruntime.NewDetectionPolicyApplication(runner)),
			Telemetry:          agentcontrol.NewTelemetryPolicyController(agentruntime.NewTelemetryPolicyApplication(runner, batcher)),
		},
	)
}
