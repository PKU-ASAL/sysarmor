package control

import policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"

func rejectedPolicyResult(identity PolicyIdentity, requestID, section, message string) Result {
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: "rejected", Message: message,
		Sections: []SectionResult{{Name: section, Status: "rejected", Message: message}},
	}
}

func endpointPolicyResult(identity PolicyIdentity, requestID string, policy policymodel.Policy, status, message string, requiresRestart bool) Result {
	telemetryStatus := "unchanged"
	telemetryMessage := "telemetry policy unchanged"
	if policy.Telemetry != nil {
		telemetryStatus = status
		telemetryMessage = "telemetry policy accepted"
	}
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: policy.PolicyID, Version: policy.Version,
		RequiresRestart: true,
		Sections: []SectionResult{
			{Name: "detection", Status: status, Message: "endpoint rules updated"},
			{Name: "response", Status: status, Message: "response policy updated"},
			{Name: "resource", Status: "unsupported", Message: "resource policy contract is reserved for the next phase", RequiresRestart: requiresRestart},
			{Name: "telemetry", Status: telemetryStatus, Message: telemetryMessage},
			{Name: "collection", Status: "unsupported", Message: "collection hot reload requires compiler/runtime apply in the next phase", RequiresRestart: true},
		},
	}
}
