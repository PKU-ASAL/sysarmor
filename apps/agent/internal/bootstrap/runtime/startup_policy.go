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

func (r *policyRuntime) loadStartupPolicy(ctx context.Context) (contract.CollectionIntent, policymodel.Policy, config.EffectiveTelemetry, error) {
	if r.management.localStore == nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, fmt.Errorf("local policy store is required")
	}
	if _, err := agentpolicy.EnsureStandaloneEndpointPolicy(ctx, r.management.localStore, r.config.Policy.Path); err != nil {
		_, source, ok, activeErr := r.management.localStore.ActivePolicy(ctx, "endpoint")
		if activeErr != nil || !ok || source != sqlite.PolicySourceManaged {
			return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
		}
		if r.out != nil {
			fmt.Fprintf(r.out, "agent standalone fallback unavailable: %v\n", err)
		}
	}
	endpoint, err := agentpolicy.LoadEffectiveEndpointPolicy(ctx, r.management.localStore, r.config.Policy.Path)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	intent, err := agentpolicy.CollectionPolicyIntent(endpoint.Collection)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	effectiveTelemetry, err := config.ResolveTelemetry(r.config.Telemetry, &endpoint.Telemetry)
	if err != nil {
		return contract.CollectionIntent{}, policymodel.Policy{}, config.EffectiveTelemetry{}, err
	}
	policy := policymodel.DefaultPolicy(r.management.currentIdentity().TenantID)
	policy.PolicyID = endpoint.PolicyID
	policy.Version = endpoint.Version
	policy.Detection = &endpoint.Detection
	policy.Telemetry = &endpoint.Telemetry
	policy.Response = endpoint.Response
	r.setEndpointPolicy(endpoint)
	r.setEffectiveTelemetry(effectiveTelemetry)
	return intent, policy, effectiveTelemetry, nil
}

func (r *policyRuntime) setEffectiveTelemetry(value config.EffectiveTelemetry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.effectiveTelemetry = value
}

func (r *policyRuntime) currentEffectiveTelemetry() config.EffectiveTelemetry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.effectiveTelemetry
}

func (r *policyRuntime) setEndpointPolicy(policy policymodel.EndpointPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endpointPolicy = policy
}

func (r *policyRuntime) currentEndpointPolicy() policymodel.EndpointPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.endpointPolicy
}

func (r *policyRuntime) persistEndpointPolicy(ctx context.Context, source sqlite.PolicySource, policy policymodel.EndpointPolicy) error {
	if r.management.localStore == nil {
		return fmt.Errorf("local policy store is required")
	}
	var err error
	if source == sqlite.PolicySourceManaged {
		err = agentpolicy.ActivateManagedEndpointPolicy(ctx, r.management.localStore, policy)
	} else {
		err = agentpolicy.SaveEffectiveEndpointPolicy(ctx, r.management.localStore, policy)
	}
	if err != nil {
		return err
	}
	r.setEndpointPolicy(policy)
	return nil
}
