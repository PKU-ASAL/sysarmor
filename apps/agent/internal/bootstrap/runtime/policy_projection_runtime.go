package runtime

import (
	"context"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

type policyProjectionRuntime struct {
	policy *policyRuntime
}

func newPolicyProjectionRuntime(policy *policyRuntime) *policyProjectionRuntime {
	return &policyProjectionRuntime{policy: policy}
}

func (r *policyProjectionRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.policy.management.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *policyProjectionRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.policy.management.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *policyProjectionRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.policy.beginLocalPolicyMutation(ctx, mutation)
}

func (r *policyProjectionRuntime) CurrentPolicySnapshot(ctx context.Context) (agentcontrol.PolicySnapshot, error) {
	policy := policymodel.Normalize(r.policy.activePolicy())
	raw, err := agentpolicy.EncodePolicyDocument(policy)
	if err != nil {
		return agentcontrol.PolicySnapshot{}, err
	}
	if endpoint := r.policy.currentEndpointPolicy(); endpoint.PolicyID != "" {
		raw, err = agentpolicy.EncodeEndpointPolicy(endpoint)
		if err != nil {
			return agentcontrol.PolicySnapshot{}, err
		}
		policy.PolicyID, policy.Version = endpoint.PolicyID, endpoint.Version
	}
	status, err := r.policy.pendingPolicyStatus(ctx)
	if err != nil {
		return agentcontrol.PolicySnapshot{}, err
	}
	snapshot := agentcontrol.PolicySnapshot{
		PolicyID: policy.PolicyID, Version: policy.Version, TenantID: policy.TenantID,
		ScopeType: policy.Scope.Type, ScopeSelector: policy.Scope.Selector, Mode: policy.Mode,
		EndpointRules: append([]string(nil), policy.EndpointRules...), CloudRules: append([]string(nil), policy.CloudRules...),
		Published: policy.Published, RawJSON: string(raw),
	}
	if status.Status != "" {
		snapshot.Pending = &agentcontrol.PendingPolicy{PolicyID: status.PolicyID, Version: status.Version, Status: status.Status, Source: agentcontrol.PolicySource(status.Source), Digest: status.Digest}
	}
	return snapshot, nil
}
