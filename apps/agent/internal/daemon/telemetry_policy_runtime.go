package daemon

import (
	"context"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type telemetryPolicyRuntime struct {
	runner  *AgentRuntime
	batcher *telemetry.Batcher
}

func newTelemetryPolicyRuntime(runner *AgentRuntime, batcher *telemetry.Batcher) *telemetryPolicyRuntime {
	return &telemetryPolicyRuntime{runner: runner, batcher: batcher}
}

func (r *telemetryPolicyRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *telemetryPolicyRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *telemetryPolicyRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *telemetryPolicyRuntime) TelemetryPolicyBaseline() config.TelemetryConfig {
	return r.runner.Config.Telemetry
}

func (r *telemetryPolicyRuntime) PersistTelemetryPolicy(ctx context.Context, policy policymodel.TelemetryPolicy) error {
	if r.runner.localStore == nil {
		return nil
	}
	endpoint := r.runner.currentEndpointPolicy()
	endpoint.Telemetry = policy
	endpoint.Version++
	return r.runner.persistEndpointPolicy(ctx, localstore.PolicySourceStandalone, endpoint)
}

func (r *telemetryPolicyRuntime) ActivateTelemetryPolicy(effective config.EffectiveTelemetry) {
	r.runner.setEffectiveTelemetry(effective)
	if r.batcher != nil {
		r.batcher.Reconfigure(telemetry.BatchSettings{
			MaxItems: effective.MaxBatchItems, MaxBytes: effective.MaxBatchBytes, FlushInterval: effective.FlushInterval,
		})
	}
}
