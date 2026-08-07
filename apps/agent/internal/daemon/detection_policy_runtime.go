package daemon

import (
	"context"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type detectionPolicyRuntime struct {
	runner *AgentRuntime
}

func newDetectionPolicyRuntime(runner *AgentRuntime) *detectionPolicyRuntime {
	return &detectionPolicyRuntime{runner: runner}
}

func (r *detectionPolicyRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *detectionPolicyRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *detectionPolicyRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *detectionPolicyRuntime) WithDetectionPolicyUpdate(run func()) {
	r.runner.withDetectionUpdateTransaction(run)
}

func (r *detectionPolicyRuntime) ActiveDetectionPolicy() policymodel.Policy {
	return r.runner.activePolicy()
}

func (r *detectionPolicyRuntime) DetectionCollectionIntent() contract.CollectionIntent {
	return r.runner.currentCollectionIntent()
}

func (r *detectionPolicyRuntime) DetectionContent() detection.ContentSnapshot {
	return r.runner.detectionContentSnapshot()
}

func (r *detectionPolicyRuntime) DetectionLimits() detection.EngineLimits {
	return r.runner.detectionLimits()
}

func (r *detectionPolicyRuntime) PersistDetectionPolicy(ctx context.Context, policy policymodel.DetectionPolicy) error {
	if r.runner.localStore == nil {
		return nil
	}
	endpoint := r.runner.currentEndpointPolicy()
	endpoint.Detection = policy
	endpoint.Version++
	return r.runner.persistEndpointPolicy(ctx, localstore.PolicySourceStandalone, endpoint)
}

func (r *detectionPolicyRuntime) RecordRejectedDetection(policy policymodel.Policy, report detection.ApplyReport) {
	r.runner.setDetectionStatus(policy, report, r.runner.contentStore().Snapshot())
}

func (r *detectionPolicyRuntime) ActivateDetectionPolicy(policy policymodel.Policy, engine *detection.Engine, report detection.ApplyReport) {
	r.runner.setPolicy(policy)
	r.runner.setDetection(engine)
	r.runner.setDetectionStatus(policy, report, r.runner.contentStore().Snapshot())
}
