package control

import (
	"context"
	"encoding/json"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type PolicyControllerRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	ActivePolicySnapshot() policymodel.Policy
	EndpointPolicySnapshot() agentpolicy.EndpointPolicy
	PendingPolicySnapshot(context.Context) (*PendingPolicy, error)
}

func (c *ApplicationPolicyController) CurrentPolicy(ctx context.Context) (PolicySnapshot, error) {
	policy := policymodel.Normalize(c.runtime.ActivePolicySnapshot())
	document := any(policy)
	if endpoint := c.runtime.EndpointPolicySnapshot(); endpoint.PolicyID != "" {
		document = endpoint
		policy.PolicyID = endpoint.PolicyID
		policy.Version = endpoint.Version
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return PolicySnapshot{}, err
	}
	pending, err := c.runtime.PendingPolicySnapshot(ctx)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return policySnapshot(policy, raw, pending), nil
}

func policySnapshot(policy policymodel.Policy, raw []byte, pending *PendingPolicy) PolicySnapshot {
	snapshot := PolicySnapshot{
		PolicyID: policy.PolicyID, Version: policy.Version, TenantID: policy.TenantID,
		ScopeType: policy.Scope.Type, ScopeSelector: policy.Scope.Selector, Mode: policy.Mode,
		EndpointRules: append([]string(nil), policy.EndpointRules...), CloudRules: append([]string(nil), policy.CloudRules...),
		Published: policy.Published, RawJSON: string(raw),
	}
	if pending != nil {
		copy := *pending
		snapshot.Pending = &copy
	}
	return snapshot
}
