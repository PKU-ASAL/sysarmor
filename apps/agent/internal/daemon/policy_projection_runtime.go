package daemon

import (
	"context"
	"fmt"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func (r *AgentRuntime) beginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
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
	runner *AgentRuntime
}

func newPolicyProjectionRuntime(runner *AgentRuntime) *policyProjectionRuntime {
	return &policyProjectionRuntime{runner: runner}
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

func (r *policyProjectionRuntime) ActivePolicySnapshot() policymodel.Policy {
	return r.runner.activePolicy()
}

func (r *policyProjectionRuntime) EndpointPolicySnapshot() agentpolicy.EndpointPolicy {
	return r.runner.currentEndpointPolicy()
}

func (r *policyProjectionRuntime) PendingPolicySnapshot(ctx context.Context) (*agentcontrol.PendingPolicy, error) {
	status, err := r.runner.pendingPolicyStatus(ctx)
	if err != nil || status.Status == "" {
		return nil, err
	}
	return &agentcontrol.PendingPolicy{
		PolicyID: status.PolicyID, Version: status.Version, Status: status.Status,
		Source: agentcontrol.PolicySource(status.Source), Digest: status.Digest,
	}, nil
}
