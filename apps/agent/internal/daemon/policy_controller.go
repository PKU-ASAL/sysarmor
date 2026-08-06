package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type policyController struct {
	runner  *AgentRuntime
	runtime sensorruntime.Runtime
	batcher *telemetry.Batcher
}

func newPolicyController(runner *AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetry.Batcher) *policyController {
	return &policyController{runner: runner, runtime: runtime, batcher: batcher}
}

func (c *policyController) ApplyPolicy(ctx context.Context, command agentcontrol.PolicyCommand) agentcontrol.Result {
	policyType := strings.TrimSpace(command.PolicyType)
	if policyType == "" {
		policyType = "endpoint"
	}
	if command.Source == agentcontrol.PolicySourceManaged || policyType == "endpoint" {
		command.PolicyType = "endpoint"
		batcher := c.batcher
		if command.Source == agentcontrol.PolicySourceManaged {
			batcher = nil
		}
		return agentcontrol.NewEndpointPolicyController(newEndpointPolicyRuntime(c.runner, c.runtime, batcher)).Apply(ctx, command)
	}
	if policyType == "telemetry" {
		return agentcontrol.NewTelemetryPolicyController(newTelemetryPolicyRuntime(c.runner, c.batcher)).Apply(ctx, command)
	}
	if policyType == "detection" {
		return agentcontrol.NewDetectionPolicyController(newDetectionPolicyRuntime(c.runner)).Apply(ctx, command)
	}
	req := applyPolicyRequest(command)
	if err := c.runner.validateControlContext(req.GetContext()); err != nil {
		return controlResult(rejectedAck(c.runner.Config, req.GetContext(), "policy", err.Error()))
	}
	return controlResult(c.applyStandalonePolicy(ctx, req, policyType))
}

func (c *policyController) applyStandalonePolicy(ctx context.Context, req *controlplanev1.ApplyPolicyRequest, policyType string) *controlplanev1.ControlAck {
	release, err := c.runner.beginLocalPolicyMutation(ctx, !req.GetDryRun())
	if err != nil {
		return rejectedAck(c.runner.Config, req.GetContext(), policyType, err.Error())
	}
	defer release()
	switch policyType {
	case "collection":
		return c.applyCollectionPolicy(ctx, req)
	default:
		return rejectedAck(c.runner.Config, req.GetContext(), "policy", fmt.Sprintf("unsupported policy type %q", policyType))
	}
}

func (c *policyController) CurrentPolicy(ctx context.Context) (agentcontrol.PolicySnapshot, error) {
	policy := policymodel.Normalize(c.runner.activePolicy())
	document := any(policy)
	if endpoint := c.runner.currentEndpointPolicy(); endpoint.PolicyID != "" {
		document = endpoint
		policy.PolicyID = endpoint.PolicyID
		policy.Version = endpoint.Version
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return agentcontrol.PolicySnapshot{}, err
	}
	snapshot := agentcontrol.PolicySnapshot{
		PolicyID: policy.PolicyID, Version: policy.Version, TenantID: policy.TenantID,
		ScopeType: policy.Scope.Type, ScopeSelector: policy.Scope.Selector, Mode: policy.Mode,
		EndpointRules: append([]string(nil), policy.EndpointRules...), CloudRules: append([]string(nil), policy.CloudRules...),
		Published: policy.Published, RawJSON: string(raw),
	}
	pending, err := c.runner.pendingPolicyStatus(ctx)
	if err != nil {
		return agentcontrol.PolicySnapshot{}, err
	}
	if pending.Status != "" {
		snapshot.Pending = &agentcontrol.PendingPolicy{
			PolicyID: pending.PolicyID, Version: pending.Version, Status: pending.Status,
			Source: agentcontrol.PolicySource(pending.Source), Digest: pending.Digest,
		}
	}
	return snapshot, nil
}

func applyPolicyRequest(command agentcontrol.PolicyCommand) *controlplanev1.ApplyPolicyRequest {
	req := &controlplanev1.ApplyPolicyRequest{
		Context: &controlplanev1.RequestContext{
			RequestId: command.Context.RequestID,
			TenantId:  command.Context.TenantID,
			AgentId:   command.Context.AgentID,
		},
		PolicyType: command.PolicyType,
		PolicyJson: command.Document,
		DryRun:     command.DryRun,
	}
	if command.Context.Scope != nil {
		req.Context.Scope = &controlplanev1.Scope{Type: command.Context.Scope.Type, Selector: command.Context.Scope.Selector}
	}
	if command.Telemetry != nil {
		req.Telemetry = &controlplanev1.TelemetryPolicy{
			MaxBatchItems: command.Telemetry.MaxBatchItems, MaxBatchBytes: command.Telemetry.MaxBatchBytes,
			FlushInterval: command.Telemetry.FlushInterval,
		}
	}
	return req
}

func controlResult(ack *controlplanev1.ControlAck) agentcontrol.Result {
	if ack == nil {
		return agentcontrol.Result{Status: "rejected", Message: "control result is nil"}
	}
	result := agentcontrol.Result{
		RequestID: ack.GetRequestId(), TenantID: ack.GetTenantId(), AgentID: ack.GetAgentId(),
		Status: ack.GetStatus(), Message: ack.GetMessage(), PolicyID: ack.GetPolicyId(),
		Version: ack.GetPolicyVersion(), Details: append([]string(nil), ack.GetDetails()...), ReportJSON: ack.GetReportJson(),
	}
	for _, section := range ack.GetSections() {
		if section.GetRequiresRestart() {
			result.RequiresRestart = true
		}
		result.Sections = append(result.Sections, agentcontrol.SectionResult{
			Name: section.GetName(), Status: section.GetStatus(), Message: section.GetMessage(),
			RequiresRestart: section.GetRequiresRestart(), Details: append([]string(nil), section.GetDetails()...), ReportJSON: section.GetReportJson(),
		})
	}
	return result
}
