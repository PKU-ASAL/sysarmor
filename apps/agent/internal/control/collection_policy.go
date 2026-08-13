package control

import (
	"context"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type CollectionPolicyRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	WithCollectionPolicyUpdate(func())
	CollectionObserveOnly() bool
	CollectionDefaultScope() Scope
	CollectionContent() agentpolicy.CollectionContentSnapshot
	ActiveCollectionDetectionPolicy() policymodel.Policy
	CollectionCapabilities() []contract.CollectionBehaviorCapability
	CollectionDetectionContent() detection.ContentSnapshot
	CollectionDetectionLimits() detection.EngineLimits
	CurrentCollectionIntent() contract.CollectionIntent
	ApplyCollectionIntent(context.Context, contract.CollectionIntent) error
	PersistCollectionPolicy(context.Context, agentpolicy.CollectionPolicy) error
	ActivateCollectionPolicy(contract.CollectionIntent, *detection.Engine)
}

type CollectionPolicyController struct {
	runtime CollectionPolicyRuntime
}

func NewCollectionPolicyController(runtime CollectionPolicyRuntime) *CollectionPolicyController {
	return &CollectionPolicyController{runtime: runtime}
}

func (c *CollectionPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.runtime.PolicyIdentity()
	if err := c.runtime.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.runtime.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "collection", err.Error())
	}
	defer release()
	var result Result
	c.runtime.WithCollectionPolicyUpdate(func() {
		result = c.applyLocked(ctx, command, identity)
	})
	return result
}

func (c *CollectionPolicyController) applyLocked(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	prepared, err := c.prepare(command)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "collection", err.Error())
	}
	if len(prepared.Compile.UnsupportedSelectors) > 0 {
		return collectionPolicyResult(identity, command.Context.RequestID, prepared, "rejected", "collection policy contains unsupported selectors", nil)
	}
	if command.DryRun {
		return c.dryRunResult(command.Context.RequestID, identity, prepared)
	}
	previous := c.runtime.CurrentCollectionIntent()
	if err := c.runtime.ApplyCollectionIntent(ctx, prepared.Intent); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "collection", "apply collection policy: "+err.Error())
	}
	if err := c.runtime.PersistCollectionPolicy(ctx, prepared.Policy); err != nil {
		_ = c.runtime.ApplyCollectionIntent(ctx, previous)
		return collectionPolicyResult(identity, command.Context.RequestID, prepared, "rejected", "persist collection policy: "+err.Error(), nil)
	}
	engine, report := detection.NewWithRuntimeLimits(c.runtime.ActiveCollectionDetectionPolicy().Detection, prepared.Intent, c.runtime.CollectionDetectionContent(), c.runtime.CollectionDetectionLimits())
	c.runtime.ActivateCollectionPolicy(prepared.Intent, engine)
	return appliedCollectionPolicyResult(identity, command.Context.RequestID, prepared, report)
}

func (c *CollectionPolicyController) dryRunResult(requestID string, identity PolicyIdentity, prepared PreparedCollectionPolicy) Result {
	status := "validated"
	message := "collection policy accepted in dry-run"
	if prepared.Detection.Status == "degraded" {
		status = "degraded"
		message += "; detection dependencies degraded: " + strings.Join(prepared.Detection.Warnings, "; ")
	}
	return collectionPolicyResult(identity, requestID, prepared, status, message, &prepared.Detection.Coverage)
}

func appliedCollectionPolicyResult(identity PolicyIdentity, requestID string, prepared PreparedCollectionPolicy, report detection.ApplyReport) Result {
	if report.Status == "degraded" {
		message := "collection policy applied; detection dependencies degraded: " + strings.Join(report.Warnings, "; ")
		return collectionPolicyResult(identity, requestID, prepared, "degraded", message, &report.Coverage)
	}
	return collectionPolicyResult(identity, requestID, prepared, "applied", "collection policy applied", &report.Coverage)
}
