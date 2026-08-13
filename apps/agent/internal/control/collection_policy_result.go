package control

import (
	"encoding/json"
	"fmt"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type collectionPolicyReport struct {
	contract.CollectionCompileReport
	DetectionCoverage *detection.CoverageReport `json:"detection_coverage,omitempty"`
}

func collectionPolicyResult(identity PolicyIdentity, requestID string, prepared PreparedCollectionPolicy, status, message string, coverage *detection.CoverageReport) Result {
	details := collectionPolicyDetails(prepared.Compile, coverage)
	reportJSON := collectionPolicyReportJSON(prepared.Compile, coverage)
	return Result{
		RequestID: requestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Status: status, Message: message, PolicyID: prepared.Policy.PolicyID, Version: prepared.Policy.Version,
		Details: details, ReportJSON: reportJSON,
		Sections: []SectionResult{{Name: "collection", Status: status, Message: message, Details: details, ReportJSON: reportJSON}},
	}
}

func collectionPolicyDetails(report contract.CollectionCompileReport, coverage *detection.CoverageReport) []string {
	if report.Backend == "" {
		return nil
	}
	details := []string{
		fmt.Sprintf("backend=%s", report.Backend),
		fmt.Sprintf("pushed_down_selectors=%d", len(report.PushedDownSelectors)),
		fmt.Sprintf("agent_side_selectors=%d", len(report.AgentSideSelectors)),
		fmt.Sprintf("unsupported_selectors=%d", len(report.UnsupportedSelectors)),
	}
	if len(report.ResolvedRefs) > 0 {
		details = append(details, fmt.Sprintf("resolved_refs=%d", len(report.ResolvedRefs)))
	}
	if report.GeneratedPolicyHash != "" {
		details = append(details, "generated_policy_hash="+report.GeneratedPolicyHash)
	}
	for _, warning := range report.Warnings {
		if warning != "" {
			details = append(details, "warning="+warning)
		}
	}
	return appendCollectionCoverageDetails(details, coverage)
}

func appendCollectionCoverageDetails(details []string, coverage *detection.CoverageReport) []string {
	if coverage == nil || coverage.Status == "" {
		return details
	}
	details = append(details, "detection_coverage="+coverage.Status)
	for _, warning := range coverage.Warnings {
		if warning != "" {
			details = append(details, "coverage_warning="+warning)
		}
	}
	return details
}

func collectionPolicyReportJSON(report contract.CollectionCompileReport, coverage *detection.CoverageReport) string {
	if report.Backend == "" {
		return ""
	}
	data, err := json.Marshal(collectionPolicyReport{CollectionCompileReport: report, DetectionCoverage: coverage})
	if err != nil {
		return ""
	}
	return string(data)
}
