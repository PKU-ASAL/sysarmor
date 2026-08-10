package worker

import (
	"context"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	managerpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type recordingEffectivePolicyService struct{ target domainpolicy.Target }

func (service *recordingEffectivePolicyService) EffectivePolicy(context.Context, managerapp.RequestContext, managerpolicy.EffectivePolicyQuery) (managerpolicy.EffectivePolicyResult, error) {
	panic("legacy authorized entrypoint must not be used")
}

func (service *recordingEffectivePolicyService) EffectivePolicyForTenant(_ context.Context, tenantID tenant.ID, target domainpolicy.Target) (managerpolicy.EffectivePolicyResult, error) {
	service.target = target
	return managerpolicy.EffectivePolicyResult{Policy: domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Published: true}}, nil
}

type fixedHealthRepository struct{ value identity.Health }

func (repo fixedHealthRepository) Get(context.Context, tenant.ID, identity.AgentID) (identity.Health, error) {
	return repo.value, nil
}
func (repo fixedHealthRepository) List(context.Context, tenant.ID, identity.HealthFilter) ([]identity.Health, error) {
	return nil, nil
}

func TestDetectionPoliciesUsesAgentRuntimeScope(t *testing.T) {
	tenantID := tenant.ID("tenant-a")
	service := &recordingEffectivePolicyService{}
	reader := NewDetectionPolicies(service, fixedHealthRepository{value: identity.Health{TenantID: tenantID, AgentID: "agent-a", Scope: identity.Scope{Type: "host", Selector: "prod"}}})
	policy, err := reader.Effective(context.Background(), tenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if policy.ID != "policy-a" || service.target != (domainpolicy.Target{AgentID: "agent-a", ScopeType: "host", ScopeSelector: "prod"}) {
		t.Fatalf("policy=%+v target=%+v", policy, service.target)
	}
}
