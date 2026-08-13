package remoteapi

import (
	"encoding/json"
	"fmt"

	appresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/response"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"google.golang.org/protobuf/proto"
)

func policyCommand(frame *controlplanev1.ControlFrame) agentcontrol.PolicyCommand {
	return agentcontrol.PolicyCommand{
		Context: controlRequestContext(frame), PolicyType: "endpoint",
		Document: frame.GetPolicyUpdate().GetRawJson(), Source: agentcontrol.PolicySourceManaged,
	}
}

func contentCommand(frame *controlplanev1.ControlFrame) agentcontrol.ContentCommand {
	req := contentUpdateRequest(frame)
	return agentcontrol.ContentCommand{
		Context: controlRequestContextFromRequest(req.GetContext()), Document: req.GetContentJson(),
		DryRun: req.GetDryRun(), AllowUnsigned: req.GetAllowUnsigned(), Source: agentcontrol.PolicySourceManaged,
	}
}

func contentUpdateRequest(frame *controlplanev1.ControlFrame) *controlplanev1.ApplyContentRequest {
	req := &controlplanev1.ApplyContentRequest{}
	if frame.GetContentUpdate() != nil {
		req = proto.Clone(frame.GetContentUpdate()).(*controlplanev1.ApplyContentRequest)
	}
	if req.Context == nil {
		if frame.GetContext() != nil {
			req.Context = proto.Clone(frame.GetContext()).(*controlplanev1.RequestContext)
		}
	}
	if req.Context == nil {
		req.Context = &controlplanev1.RequestContext{}
	}
	if req.Context.RequestId == "" {
		req.Context.RequestId = frame.GetRequestId()
	}
	if req.Context.TenantId == "" {
		req.Context.TenantId = frame.GetContext().GetTenantId()
	}
	if req.Context.AgentId == "" {
		req.Context.AgentId = frame.GetContext().GetAgentId()
	}
	if req.Context.Scope == nil {
		req.Context.Scope = frame.GetContext().GetScope()
	}
	return req
}

func controlRequestContext(frame *controlplanev1.ControlFrame) agentcontrol.RequestContext {
	req := frame.GetContext()
	requestID := req.GetRequestId()
	if requestID == "" {
		requestID = frame.GetRequestId()
	}
	ctx := agentcontrol.RequestContext{RequestID: requestID, TenantID: req.GetTenantId(), AgentID: req.GetAgentId()}
	if req.GetScope() != nil {
		ctx.Scope = &agentcontrol.Scope{Type: req.GetScope().GetType(), Selector: req.GetScope().GetSelector()}
	}
	return ctx
}

func controlRequestContextFromRequest(req *controlplanev1.RequestContext) agentcontrol.RequestContext {
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

func responseCommand(in *controlplanev1.ResponseCommand) (domainresponse.Command, error) {
	if in == nil {
		return domainresponse.Command{}, fmt.Errorf("control frame missing response_command")
	}
	if in.GetRawJson() != "" {
		var cmd responsemodel.Command
		if err := json.Unmarshal([]byte(in.GetRawJson()), &cmd); err != nil {
			return domainresponse.Command{}, fmt.Errorf("decode control frame response command raw_json: %w", err)
		}
		return domainResponseCommand(cmd), nil
	}
	return domainresponse.Command{
		ID: in.GetResponseId(), TenantID: in.GetTenantId(), AgentID: in.GetAgentId(),
		PolicyID: in.GetPolicyId(), PolicyVersion: in.GetPolicyVersion(), SignalID: in.GetSignalId(),
		Labels: cloneLabels(in.GetLabels()), Scope: domainresponse.Scope{Type: in.GetScope().GetType(), Selector: in.GetScope().GetSelector()},
		Action: in.GetAction(), Mode: domainresponse.Mode(in.GetMode()), Target: in.GetTarget(), Reason: in.GetReason(), Status: in.GetStatus(), Actor: in.GetActor(),
		ApprovalRequired: in.GetApprovalRequired(), ApprovalStatus: in.GetApprovalStatus(), ApprovalThreshold: in.GetApprovalThreshold(),
		ApprovalRoles: append([]string(nil), in.GetApprovalRoles()...),
	}, nil
}

func domainResponseCommand(command responsemodel.Command) domainresponse.Command {
	approvals := make([]domainresponse.Approval, 0, len(command.Approvals))
	for _, approval := range command.Approvals {
		approvals = append(approvals, domainresponse.Approval{Actor: approval.Actor, Role: approval.Role, Approved: approval.Approved})
	}
	return domainresponse.Command{
		ID: command.ResponseID, TenantID: command.TenantID, AgentID: command.AgentID,
		PolicyID: command.PolicyID, PolicyVersion: command.PolicyVersion, SignalID: command.SignalID,
		Labels: cloneLabels(command.Labels), Scope: domainresponse.Scope{Type: command.Scope.Type, Selector: command.Scope.Selector},
		Action: command.Action, Mode: domainresponse.Mode(command.Mode), Target: command.Target, Reason: command.Reason,
		Status: command.Status, Actor: command.Actor, ApprovalRequired: command.ApprovalRequired,
		ApprovalStatus: command.ApprovalStatus, ApprovalThreshold: command.ApprovalThreshold,
		ApprovalRoles: append([]string(nil), command.ApprovalRoles...), Approvals: approvals,
	}
}

func evidencePullback(in *controlplanev1.EvidencePullbackRequest) (appresponse.EvidenceRequest, error) {
	if in == nil {
		return appresponse.EvidenceRequest{}, fmt.Errorf("control frame missing evidence_pullback")
	}
	if in.GetRawJson() != "" {
		var req struct {
			RequestID string `json:"request_id"`
			Target    string `json:"target"`
		}
		if err := json.Unmarshal([]byte(in.GetRawJson()), &req); err != nil {
			return appresponse.EvidenceRequest{}, fmt.Errorf("decode control frame evidence pullback raw_json: %w", err)
		}
		return appresponse.EvidenceRequest{RequestID: req.RequestID, Target: req.Target}, nil
	}
	return appresponse.EvidenceRequest{RequestID: in.GetRequestId(), Target: in.GetTarget()}, nil
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
