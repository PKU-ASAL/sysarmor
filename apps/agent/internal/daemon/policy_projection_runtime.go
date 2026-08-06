package daemon

import (
	"context"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type policyProjectionRuntime struct {
	runner *AgentRuntime
}

func newPolicyProjectionRuntime(runner *AgentRuntime) *policyProjectionRuntime {
	return &policyProjectionRuntime{runner: runner}
}

func (r *policyProjectionRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	return agentcontrol.PolicyIdentity{TenantID: r.runner.Config.Agent.TenantID, AgentID: r.runner.Config.Agent.ID}
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
