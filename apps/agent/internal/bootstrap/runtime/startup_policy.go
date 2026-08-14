package runtime

import (
	"context"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (r *Coordinator) loadStartupPolicy(ctx context.Context) (contract.CollectionIntent, policymodel.Policy, config.EffectiveTelemetry, error) {
	if r.localStore == nil {
		return r.loadLegacyRuntimePolicy()
	}
	if _, err := agentpolicy.EnsureStandaloneEndpointPolicy(ctx, r.localStore, r.Config.Policy.Path); err != nil {
		_, source, ok, activeErr := r.localStore.ActivePolicy(ctx, "endpoint")
		if activeErr != nil || !ok || source != sqlite.PolicySourceManaged {
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

func (r *Coordinator) setEffectiveTelemetry(value config.EffectiveTelemetry) {
	r.policyRuntime.mu.Lock()
	defer r.policyRuntime.mu.Unlock()
	r.effectiveTelemetry = value
}

func (r *Coordinator) currentEffectiveTelemetry() config.EffectiveTelemetry {
	r.policyRuntime.mu.RLock()
	defer r.policyRuntime.mu.RUnlock()
	return r.effectiveTelemetry
}

func (r *Coordinator) setEndpointPolicy(policy policymodel.EndpointPolicy) {
	r.policyRuntime.mu.Lock()
	defer r.policyRuntime.mu.Unlock()
	r.endpointPolicy = policy
}

func (r *Coordinator) currentEndpointPolicy() policymodel.EndpointPolicy {
	r.policyRuntime.mu.RLock()
	defer r.policyRuntime.mu.RUnlock()
	return r.endpointPolicy
}

func (r *Coordinator) persistEndpointPolicy(ctx context.Context, source sqlite.PolicySource, policy policymodel.EndpointPolicy) error {
	if r.localStore == nil {
		r.setEndpointPolicy(policy)
		return nil
	}
	var err error
	if source == sqlite.PolicySourceManaged {
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

func (r *Coordinator) loadLegacyRuntimePolicy() (contract.CollectionIntent, policymodel.Policy, config.EffectiveTelemetry, error) {
	intent, err := agentpolicy.LoadCollectionIntent(r.Config.Sensor.PolicyPath, r.Config.Sensor.ObserveOnly)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	policy := r.activePolicy()
	effectiveTelemetry, err := config.ResolveTelemetry(r.Config.Telemetry, policy.Telemetry)
	return intent, policy, effectiveTelemetry, err
}
