package bootstrap

import (
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	agentruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/bootstrap/runtime"
)

func newPolicyController(runtime agentcontrol.PolicyControllerRuntime, applications agentruntime.PolicyApplications) *agentcontrol.ApplicationPolicyController {
	return agentcontrol.NewApplicationPolicyController(runtime, agentcontrol.PolicyUseCases{
		StandaloneEndpoint: agentcontrol.NewEndpointPolicyController(applications.StandaloneEndpoint),
		ManagedEndpoint:    agentcontrol.NewEndpointPolicyController(applications.ManagedEndpoint),
		Collection:         agentcontrol.NewCollectionPolicyController(applications.Collection),
		Detection:          agentcontrol.NewDetectionPolicyController(applications.Detection),
		Telemetry:          agentcontrol.NewTelemetryPolicyController(applications.Telemetry),
	})
}
