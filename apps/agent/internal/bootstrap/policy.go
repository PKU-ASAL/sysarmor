package bootstrap

import (
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/daemon"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
)

func newPolicyController(runner *daemon.AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(
		daemon.NewPolicyProjectionRuntime(runner),
		agentcontrol.PolicyUseCases{
			StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(daemon.NewEndpointPolicyApplication(runner, runtime, batcher)),
			ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(daemon.NewEndpointPolicyApplication(runner, runtime, nil)),
			Collection:         agentcontrol.NewCollectionPolicyController(daemon.NewCollectionPolicyApplication(runner, runtime)),
			Detection:          agentcontrol.NewDetectionPolicyController(daemon.NewDetectionPolicyApplication(runner)),
			Telemetry:          agentcontrol.NewTelemetryPolicyController(daemon.NewTelemetryPolicyApplication(runner, batcher)),
		},
	)
}
