package runtime

import (
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
)

func newApplicationPolicyController(runner *Coordinator, runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController {
	runner.wireComponents()
	runner.policyState.controller = newTestPolicyController
	return runner.policyState.policyController(runtime, batcher)
}

func newTestPolicyController(runtime agentcontrol.PolicyControllerRuntime, applications PolicyApplications) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(runtime, agentcontrol.PolicyUseCases{
		StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(applications.StandaloneEndpoint),
		ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(applications.ManagedEndpoint),
		Collection:         agentcontrol.NewCollectionPolicyController(applications.Collection),
		Detection:          agentcontrol.NewDetectionPolicyController(applications.Detection),
		Telemetry:          agentcontrol.NewTelemetryPolicyController(applications.Telemetry),
	})
}

func newTestContentApplicationAdapter(runner *Coordinator) *contentApplicationAdapter {
	runner.wireComponents()
	return newContentApplicationAdapter(&runner.policyState)
}
