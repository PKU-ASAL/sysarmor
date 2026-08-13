package control

import (
	"encoding/json"
	"strings"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func endpointApplicationResult(identity PolicyIdentity, requestID string, candidate applicationpolicy.EndpointCandidate, report applicationpolicy.EndpointReport) Result {
	status := report.Status
	if status == "" {
		status = "applied"
	}
	message := report.Message
	if message == "" {
		message = "endpoint policy applied"
	}
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: candidate.PolicyID(), Version: candidate.PolicyVersion(),
		RequiresRestart: report.RequiresRestart,
		Sections: []SectionResult{
			{Name: "detection", Status: status, Message: "endpoint rules updated"},
			{Name: "response", Status: status, Message: "response policy updated"},
			{Name: "resource", Status: "unsupported", Message: "resource policy contract is reserved for the next phase", RequiresRestart: report.RequiresRestart},
			{Name: "telemetry", Status: status, Message: "telemetry policy accepted"},
			{Name: "collection", Status: status, Message: "collection policy accepted", RequiresRestart: report.RequiresRestart},
		},
	}
}

func rejectedPolicyResult(identity PolicyIdentity, requestID, section, message string) Result {
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: "rejected", Message: message,
		Sections: []SectionResult{{Name: section, Status: "rejected", Message: message}},
	}
}

func telemetryPolicyResult(identity PolicyIdentity, requestID, status, message string, policy policymodel.TelemetryPolicy) Result {
	report, _ := json.Marshal(map[string]any{"telemetry": policy})
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, ReportJSON: string(report),
		Sections: []SectionResult{{Name: "telemetry", Status: status, Message: message, ReportJSON: string(report)}},
	}
}

func detectionPolicyResult(identity PolicyIdentity, requestID string, policy policymodel.Policy, status, message string, report detection.ApplyReport) Result {
	if status == "" {
		status = "applied"
	}
	if message == "" {
		message = "detection policy applied"
	}
	if len(report.Details) > 0 {
		message += ": " + strings.Join(report.Details, "; ")
	}
	reportJSON, _ := json.Marshal(report)
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: policy.PolicyID, Version: policy.Version, ReportJSON: string(reportJSON),
		Sections: []SectionResult{{Name: "detection", Status: status, Message: message, ReportJSON: string(reportJSON)}},
	}
}
