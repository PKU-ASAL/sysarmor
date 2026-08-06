package daemon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func appliedAck(cfg config.Config, req *controlplanev1.RequestContext, policy policymodel.Policy, status, message string, requiresRestart bool) *controlplanev1.ControlAck {
	telemetryStatus := "unchanged"
	telemetryMessage := "telemetry policy unchanged"
	if policy.Telemetry != nil {
		telemetryStatus = status
		telemetryMessage = "telemetry policy accepted"
	}
	return &controlplanev1.ControlAck{
		RequestId:     requestID(req),
		TenantId:      cfg.Agent.TenantID,
		AgentId:       cfg.Agent.ID,
		Status:        status,
		Message:       message,
		PolicyId:      policy.PolicyID,
		PolicyVersion: policy.Version,
		Sections: []*controlplanev1.AppliedSection{
			{Name: "detection", Status: status, Message: "endpoint rules updated", RequiresRestart: false},
			{Name: "response", Status: status, Message: "response policy updated", RequiresRestart: false},
			{Name: "resource", Status: "unsupported", Message: "resource policy contract is reserved for the next phase", RequiresRestart: requiresRestart},
			{Name: "telemetry", Status: telemetryStatus, Message: telemetryMessage, RequiresRestart: false},
			{Name: "collection", Status: "unsupported", Message: "collection hot reload requires compiler/runtime apply in the next phase", RequiresRestart: true},
		},
	}
}

func requestScope(req *controlplanev1.RequestContext) config.RuntimeScope {
	if req == nil || req.GetScope() == nil {
		return config.RuntimeScope{}
	}
	return config.RuntimeScope{Type: req.GetScope().GetType(), Selector: req.GetScope().GetSelector()}
}

func collectionContentSnapshot(snapshot agentcontent.Snapshot) agentpolicy.CollectionContentSnapshot {
	out := agentpolicy.CollectionContentSnapshot{
		ContextSets: make(map[string]agentpolicy.CollectionValueSet, len(snapshot.ContextSets)),
		IOCPacks:    make(map[string]agentpolicy.CollectionValueSet, len(snapshot.IOCPacks)),
	}
	for ref, set := range snapshot.ContextSets {
		out.ContextSets[ref] = collectionValueSet(set)
	}
	for ref, set := range snapshot.IOCPacks {
		out.IOCPacks[ref] = collectionValueSet(set)
	}
	return out
}

func collectionValueSet(set agentcontent.ValueSet) agentpolicy.CollectionValueSet {
	return agentpolicy.CollectionValueSet{
		Ref:       set.Ref,
		Version:   set.Version,
		Digest:    set.Digest,
		ValueType: set.ValueType,
		Values:    append([]string(nil), set.Values...),
	}
}

type collectionExplainReport struct {
	contract.CollectionCompileReport
	DetectionCoverage *detection.CoverageReport `json:"detection_coverage,omitempty"`
}

func collectionAck(cfg config.Config, req *controlplanev1.RequestContext, policy agentpolicy.CollectionPolicy, status, message string, requiresRestart bool, report contract.CollectionCompileReport, coverage *detection.CoverageReport) *controlplanev1.ControlAck {
	details := collectionReportDetails(report, coverage)
	reportJSON := collectionReportJSON(report, coverage)
	return &controlplanev1.ControlAck{
		RequestId:     requestID(req),
		TenantId:      cfg.Agent.TenantID,
		AgentId:       cfg.Agent.ID,
		Status:        status,
		Message:       message,
		PolicyId:      policy.PolicyID,
		PolicyVersion: policy.Version,
		Details:       details,
		ReportJson:    reportJSON,
		Sections: []*controlplanev1.AppliedSection{{
			Name:            "collection",
			Status:          status,
			Message:         message,
			RequiresRestart: requiresRestart,
			Details:         details,
			ReportJson:      reportJSON,
		}},
	}
}

func collectionReportDetails(report contract.CollectionCompileReport, coverage *detection.CoverageReport) []string {
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
	if coverage != nil && coverage.Status != "" {
		details = append(details, "detection_coverage="+coverage.Status)
		for _, warning := range coverage.Warnings {
			if warning != "" {
				details = append(details, "coverage_warning="+warning)
			}
		}
	}
	return details
}

func collectionReportJSON(report contract.CollectionCompileReport, coverage *detection.CoverageReport) string {
	if report.Backend == "" {
		return ""
	}
	out := collectionExplainReport{CollectionCompileReport: report}
	if coverage != nil {
		out.DetectionCoverage = coverage
	}
	data, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(data)
}

func detectionAck(cfg config.Config, req *controlplanev1.RequestContext, policy policymodel.Policy, status, message string, requiresRestart bool, report detection.ApplyReport) *controlplanev1.ControlAck {
	if status == "" {
		status = "applied"
	}
	if message == "" {
		message = "detection policy applied"
	}
	sectionMessage := message
	if len(report.Details) > 0 {
		sectionMessage = sectionMessage + ": " + strings.Join(report.Details, "; ")
	}
	reportJSON := detectionReportJSON(report)
	return &controlplanev1.ControlAck{
		RequestId:     requestID(req),
		TenantId:      cfg.Agent.TenantID,
		AgentId:       cfg.Agent.ID,
		Status:        status,
		Message:       sectionMessage,
		PolicyId:      policy.PolicyID,
		PolicyVersion: policy.Version,
		Sections: []*controlplanev1.AppliedSection{{
			Name:            "detection",
			Status:          status,
			Message:         sectionMessage,
			RequiresRestart: requiresRestart,
			ReportJson:      reportJSON,
		}},
		ReportJson: reportJSON,
	}
}

func detectionReportJSON(report detection.ApplyReport) string {
	data, err := json.Marshal(report)
	if err != nil {
		return ""
	}
	return string(data)
}
