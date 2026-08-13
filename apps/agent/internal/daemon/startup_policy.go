package daemon

import (
	"context"
	"fmt"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (r *AgentRuntime) loadStartupPolicy(ctx context.Context) (contract.CollectionIntent, policymodel.Policy, config.EffectiveTelemetry, error) {
	if r.localStore == nil {
		return r.loadLegacyRuntimePolicy()
	}
	if _, err := agentpolicy.EnsureStandaloneEndpointPolicy(ctx, r.localStore, r.Config.Policy.Path); err != nil {
		_, source, ok, activeErr := r.localStore.ActivePolicy(ctx, "endpoint")
		if activeErr != nil || !ok || source != localstore.PolicySourceManaged {
			return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
		}
		if r.Out != nil {
			fmt.Fprintf(r.Out, "agent standalone fallback unavailable: %v\n", err)
		}
	}
	endpoint, err := agentpolicy.LoadEffectiveEndpointPolicy(ctx, r.localStore, r.Config.Policy.Path)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	intent, err := agentpolicy.CollectionPolicyIntent(endpoint.Collection)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	effectiveTelemetry, err := config.ResolveTelemetry(r.Config.Telemetry, &endpoint.Telemetry)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	policy := policymodel.DefaultPolicy(r.currentIdentity().TenantID)
	policy.PolicyID = endpoint.PolicyID
	policy.Version = endpoint.Version
	policy.Detection = &endpoint.Detection
	policy.Telemetry = &endpoint.Telemetry
	policy.Response = endpoint.Response
	r.setEndpointPolicy(endpoint)
	r.setEffectiveTelemetry(effectiveTelemetry)
	return intent, policy, effectiveTelemetry, nil
}

func (r *AgentRuntime) setEffectiveTelemetry(value config.EffectiveTelemetry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.effectiveTelemetry = value
}

func (r *AgentRuntime) currentEffectiveTelemetry() config.EffectiveTelemetry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.effectiveTelemetry
}

func (r *AgentRuntime) setEndpointPolicy(policy agentpolicy.EndpointPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpointPolicy = policy
}

func (r *AgentRuntime) currentEndpointPolicy() agentpolicy.EndpointPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.endpointPolicy
}

func (r *AgentRuntime) persistEndpointPolicy(ctx context.Context, source localstore.PolicySource, policy agentpolicy.EndpointPolicy) error {
	if r.localStore == nil {
		r.setEndpointPolicy(policy)
		return nil
	}
	var err error
	if source == localstore.PolicySourceManaged {
		err = agentpolicy.ActivateManagedEndpointPolicy(ctx, r.localStore, policy)
	} else {
		err = agentpolicy.SaveEffectiveEndpointPolicy(ctx, r.localStore, policy)
	}
	if err != nil {
		return err
	}
	r.setEndpointPolicy(policy)
	return nil
}

func (r *AgentRuntime) loadLegacyRuntimePolicy() (contract.CollectionIntent, policymodel.Policy, config.EffectiveTelemetry, error) {
	intent, err := agentpolicy.LoadCollectionIntent(r.Config.Sensor.PolicyPath, r.Config.Sensor.ObserveOnly)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	policy := r.activePolicy()
	effectiveTelemetry, err := config.ResolveTelemetry(r.Config.Telemetry, policy.Telemetry)
	return intent, policy, effectiveTelemetry, err
}
