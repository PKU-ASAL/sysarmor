package runtime

import (
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func remoteCapabilityResponse(health agenthealth.AgentHealth) *controlplanev1.CapabilityResponse {
	return &controlplanev1.CapabilityResponse{
		AgentId:                  health.AgentID,
		HostId:                   health.HostID,
		TenantId:                 health.TenantID,
		Scope:                    scopeMessage(health.Scope),
		Sensor:                   capabilityMessage(health.Capability),
		SupportedPolicySections:  []string{"collection", "detection", "telemetry"},
		SupportedResponseActions: []string{"collect", "noop"},
		CollectionBehaviors:      collectionBehaviorMessages(health.Capability.Collection),
	}
}
