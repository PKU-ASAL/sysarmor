package localapi

import (
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	appenrollment "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func policyCommand(req *controlplanev1.ApplyPolicyRequest) agentcontrol.PolicyCommand {
	command := agentcontrol.PolicyCommand{
		Context: controlRequestContext(req.GetContext()), PolicyType: req.GetPolicyType(),
		Document: req.GetPolicyJson(), DryRun: req.GetDryRun(), Source: agentcontrol.PolicySourceStandalone,
	}
	if req.GetTelemetry() != nil {
		command.Telemetry = &agentcontrol.TelemetryPolicy{
			MaxBatchItems: req.GetTelemetry().GetMaxBatchItems(), MaxBatchBytes: req.GetTelemetry().GetMaxBatchBytes(),
			FlushInterval: req.GetTelemetry().GetFlushInterval(),
		}
	}
	return command
}

func contentCommand(req *controlplanev1.ApplyContentRequest) agentcontrol.ContentCommand {
	return agentcontrol.ContentCommand{
		Context: controlRequestContext(req.GetContext()), Document: req.GetContentJson(),
		DryRun: req.GetDryRun(), AllowUnsigned: req.GetAllowUnsigned(), Source: agentcontrol.PolicySourceStandalone,
	}
}

func enrollmentCommand(req *controlplanev1.EnrollRequest) appenrollment.EnrollmentCommand {
	return appenrollment.EnrollmentCommand{
		Context: lifecycleRequestContext(req.GetContext()), ManagerURL: req.GetManagerUrl(),
		Token: req.GetEnrollmentToken(), UploadHistory: req.GetUploadHistory(),
	}
}

func unenrollmentCommand(req *controlplanev1.UnenrollRequest) appenrollment.UnenrollmentCommand {
	return appenrollment.UnenrollmentCommand{Context: lifecycleRequestContext(req.GetContext())}
}

func lifecycleRequestContext(req *controlplanev1.RequestContext) lifecycle.RequestContext {
	ctx := lifecycle.RequestContext{RequestID: req.GetRequestId(), TenantID: req.GetTenantId(), AgentID: req.GetAgentId()}
	if req.GetScope() != nil {
		ctx.Scope = &lifecycle.Scope{Type: req.GetScope().GetType(), Selector: req.GetScope().GetSelector()}
	}
	return ctx
}

func controlRequestContext(req *controlplanev1.RequestContext) agentcontrol.RequestContext {
	ctx := agentcontrol.RequestContext{RequestID: req.GetRequestId(), TenantID: req.GetTenantId(), AgentID: req.GetAgentId()}
	if req.GetScope() != nil {
		ctx.Scope = &agentcontrol.Scope{Type: req.GetScope().GetType(), Selector: req.GetScope().GetSelector()}
	}
	return ctx
}

func controlAck(result agentcontrol.Result) *controlplanev1.ControlAck {
	ack := &controlplanev1.ControlAck{
		RequestId: result.RequestID, TenantId: result.TenantID, AgentId: result.AgentID,
		Status: result.Status, Message: result.Message, PolicyId: result.PolicyID,
		PolicyVersion: result.Version, Details: append([]string(nil), result.Details...), ReportJson: result.ReportJSON,
	}
	for _, section := range result.Sections {
		ack.Sections = append(ack.Sections, &controlplanev1.AppliedSection{
			Name: section.Name, Status: section.Status, Message: section.Message,
			RequiresRestart: section.RequiresRestart, Details: append([]string(nil), section.Details...), ReportJson: section.ReportJSON,
		})
	}
	return ack
}

func enrollmentAck(result lifecycle.Result) *controlplanev1.ControlAck {
	return &controlplanev1.ControlAck{
		RequestId: result.RequestID, TenantId: result.TenantID, AgentId: result.AgentID,
		Status: string(result.Status), Message: result.Message,
	}
}

func contentRecordMessage(record agentcontent.Record) *controlplanev1.ContentRecord {
	return &controlplanev1.ContentRecord{
		Ref: record.Ref, Kind: record.Kind, Version: record.Version, Digest: record.Digest,
		Signed: record.Signed, Status: record.Status, RawJson: record.RawJSON,
	}
}

func currentPolicyMessage(snapshot agentcontrol.PolicySnapshot) *controlplanev1.CurrentPolicyResponse {
	response := &controlplanev1.CurrentPolicyResponse{
		PolicyId: snapshot.PolicyID, Version: snapshot.Version, TenantId: snapshot.TenantID,
		Scope: &controlplanev1.Scope{Type: snapshot.ScopeType, Selector: snapshot.ScopeSelector},
		Mode:  snapshot.Mode, EndpointRules: append([]string(nil), snapshot.EndpointRules...),
		CloudRules: append([]string(nil), snapshot.CloudRules...), Published: snapshot.Published, RawJson: snapshot.RawJSON,
	}
	if snapshot.Pending != nil {
		response.PendingPolicy = &controlplanev1.PendingPolicyStatus{
			Status: snapshot.Pending.Status, Source: string(snapshot.Pending.Source), PolicyId: snapshot.Pending.PolicyID,
			Version: snapshot.Pending.Version, Digest: snapshot.Pending.Digest,
		}
	}
	return response
}
