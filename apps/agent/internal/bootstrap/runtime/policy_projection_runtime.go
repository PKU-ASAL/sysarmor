package runtime

import (
	"context"
	"fmt"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func (r *Coordinator) beginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	if !mutation {
		return func() {}, nil
	}
	r.policyAuthorityMu.RLock()
	if r.localStore == nil {
		r.policyAuthorityMu.RUnlock()
		return nil, fmt.Errorf("local store is unavailable")
	}
	enrollment, err := r.localStore.Enrollment(ctx)
	if err != nil {
		r.policyAuthorityMu.RUnlock()
		return nil, fmt.Errorf("read enrollment state: %w", err)
	}
	mode, err := management.Resolve(enrollment.State)
	if err == nil {
		err = mode.Authorize(management.PolicyWriteLocal)
	}
	if err != nil {
		r.policyAuthorityMu.RUnlock()
		return nil, err
	}
	return r.policyAuthorityMu.RUnlock, nil
}

type policyProjectionRuntime struct {
	runner *Coordinator
}

func newPolicyProjectionRuntime(runner *Coordinator) *policyProjectionRuntime {
	return &policyProjectionRuntime{runner: runner}
}

func NewPolicyProjectionRuntime(runner *Coordinator) agentcontrol.PolicyControllerRuntime {
	return newPolicyProjectionRuntime(runner)
}

func (r *policyProjectionRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *policyProjectionRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *policyProjectionRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *policyProjectionRuntime) CurrentPolicySnapshot(ctx context.Context) (agentcontrol.PolicySnapshot, error) {
	policy := policymodel.Normalize(r.runner.activePolicy())
	raw, err := agentpolicy.EncodePolicyDocument(policy)
	if err != nil {
		return agentcontrol.PolicySnapshot{}, err
	}
	if endpoint := r.runner.currentEndpointPolicy(); endpoint.PolicyID != "" {
		raw, err = agentpolicy.EncodeEndpointPolicy(endpoint)
		if err != nil {
			return agentcontrol.PolicySnapshot{}, err
		}
		policy.PolicyID, policy.Version = endpoint.PolicyID, endpoint.Version
	}
	status, err := r.runner.pendingPolicyStatus(ctx)
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
