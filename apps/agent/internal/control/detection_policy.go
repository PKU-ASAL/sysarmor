package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type DetectionPolicyRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	WithDetectionPolicyUpdate(func())
	ActiveDetectionPolicy() policymodel.Policy
	DetectionCollectionIntent() contract.CollectionIntent
	DetectionContent() detection.ContentSnapshot
	DetectionLimits() detection.EngineLimits
	PersistDetectionPolicy(context.Context, policymodel.DetectionPolicy) error
	RecordRejectedDetection(policymodel.Policy, detection.ApplyReport)
	ActivateDetectionPolicy(policymodel.Policy, *detection.Engine, detection.ApplyReport)
}

type DetectionPolicyController struct {
	runtime DetectionPolicyRuntime
}

func NewDetectionPolicyController(runtime DetectionPolicyRuntime) *DetectionPolicyController {
	return &DetectionPolicyController{runtime: runtime}
}

func (c *DetectionPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.runtime.PolicyIdentity()
	if err := c.runtime.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.runtime.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "detection", err.Error())
	}
	defer release()
	var result Result
	c.runtime.WithDetectionPolicyUpdate(func() {
		result = c.applyLocked(ctx, command, identity)
	})
	return result
}

func (c *DetectionPolicyController) applyLocked(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	policy, active, engine, report, err := c.prepare(command.Document)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "detection", err.Error())
	}
	if command.DryRun {
		return detectionPolicyResult(identity, command.Context.RequestID, active, report.Status, "detection policy accepted in dry-run: "+report.Message, report)
	}
	if report.Status == "rejected" {
		c.runtime.RecordRejectedDetection(active, report)
		return detectionPolicyResult(identity, command.Context.RequestID, active, "rejected", "detection policy rejected: "+strings.Join(report.Details, "; "), report)
	}
	if err := c.runtime.PersistDetectionPolicy(ctx, policy); err != nil {
		return detectionPolicyResult(identity, command.Context.RequestID, active, "rejected", "persist detection policy: "+err.Error(), report)
	}
	c.runtime.ActivateDetectionPolicy(active, engine, report)
	return detectionPolicyResult(identity, command.Context.RequestID, active, report.Status, report.Message, report)
}

func (c *DetectionPolicyController) prepare(document string) (policymodel.DetectionPolicy, policymodel.Policy, *detection.Engine, detection.ApplyReport, error) {
	policy, err := parseDetectionPolicy(document)
	if err != nil {
		return policymodel.DetectionPolicy{}, policymodel.Policy{}, nil, detection.ApplyReport{}, err
	}
	policy = policymodel.NormalizeDetectionPolicy(policy)
	engine, report := detection.NewWithRuntimeLimits(&policy, c.runtime.DetectionCollectionIntent(), c.runtime.DetectionContent(), c.runtime.DetectionLimits())
	active := policymodel.Normalize(c.runtime.ActiveDetectionPolicy())
	active.Detection = &policy
	return policy, active, engine, report, nil
}

func parseDetectionPolicy(document string) (policymodel.DetectionPolicy, error) {
	var envelope struct {
		Detection *policymodel.DetectionPolicy `json:"detection"`
	}
	if err := json.Unmarshal([]byte(document), &envelope); err == nil && envelope.Detection != nil {
		return *envelope.Detection, nil
	}
	var policy policymodel.DetectionPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return policymodel.DetectionPolicy{}, fmt.Errorf("invalid detection policy json: %w", err)
	}
	return policy, nil
}
