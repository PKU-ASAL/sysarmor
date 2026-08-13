package bootstrap

import (
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/daemon"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
)

func newPolicyController(runner *daemon.AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetry.Batcher) *agentcontrol.ApplicationPolicyController {
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
