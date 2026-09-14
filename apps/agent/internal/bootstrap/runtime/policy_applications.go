package runtime

import (
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
)

func (r *policyRuntime) policyController(runtime sensorruntime.Runtime, batcher *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController {
	applications := PolicyApplications{
		StandaloneEndpoint: newEndpointPolicyApplication(r, runtime, batcher),
		ManagedEndpoint:    newEndpointPolicyApplication(r, runtime, nil),
		Collection:         newCollectionPolicyApplication(r, runtime),
		Detection:          newDetectionPolicyApplication(r),
		Telemetry:          newTelemetryPolicyApplication(r, batcher),
	}
	return r.controller(newPolicyProjectionRuntime(r), applications)
}
