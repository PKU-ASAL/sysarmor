package worker

import (
	"context"

	managerpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type effectivePolicyService interface {
	EffectivePolicyForTenant(context.Context, tenant.ID, domainpolicy.Target) (managerpolicy.EffectivePolicyResult, error)
}

type DetectionPolicies struct {
	policies effectivePolicyService
	health   ports.AgentHealthRepository
}

func NewDetectionPolicies(policies effectivePolicyService, health ports.AgentHealthRepository) *DetectionPolicies {
	return &DetectionPolicies{policies: policies, health: health}
}

func (reader *DetectionPolicies) Effective(ctx context.Context, tenantID tenant.ID, agentID identity.AgentID) (domainpolicy.Policy, error) {
	target := domainpolicy.Target{AgentID: string(agentID)}
	health, err := reader.health.Get(ctx, tenantID, agentID)
	if err == nil {
		target.ScopeType, target.ScopeSelector = health.Scope.Type, health.Scope.Selector
	} else if failure.KindOf(err) != failure.NotFound {
		return domainpolicy.Policy{}, err
	}
	result, err := reader.policies.EffectivePolicyForTenant(ctx, tenantID, target)
	return result.Policy, err
}
