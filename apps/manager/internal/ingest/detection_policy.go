package ingestworker

import (
	"context"
	"encoding/json"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type storeDetectionPolicies struct{ store *store.Store }

func (reader storeDetectionPolicies) Effective(_ context.Context, tenantID tenant.ID, agentID identity.AgentID) (domainpolicy.Policy, error) {
	var scopeType, scopeSelector string
	if health, ok := reader.store.GetAgentHealth(tenantID.String(), string(agentID)); ok {
		scopeType, scopeSelector = health.Scope.Type, health.Scope.Selector
	}
	policy, _ := reader.store.EffectivePolicy(tenantID.String(), string(agentID), scopeType, scopeSelector)
	document, err := json.Marshal(policy)
	return domainpolicy.Policy{TenantID: tenantID, ID: domainpolicy.ID(policy.PolicyID), Version: domainpolicy.Version(policy.Version), Published: policy.Published, Document: document}, err
}
