package control

import applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"

func collectionApplicationResult(identity PolicyIdentity, requestID string, candidate applicationpolicy.CollectionCandidate, report applicationpolicy.CollectionReport) Result {
	status := report.Status
	if status == "" {
		status = "validated"
	}
	message := report.Message
	if message == "" {
		message = "collection policy accepted"
	}
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: candidate.PolicyID(), Version: candidate.PolicyVersion(),
		Details: append([]string(nil), report.Warnings...), ReportJSON: report.ReportJSON,
		Sections: []SectionResult{{Name: "collection", Status: status, Message: message, Details: append([]string(nil), report.Warnings...), ReportJSON: report.ReportJSON}},
	}
}
