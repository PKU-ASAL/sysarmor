package policy

import (
	"context"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

func TestQueryPoliciesUsesActorTenant(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 1})
	service := NewQueryService(uow)

	result, err := service.ListPolicies(context.Background(), requestContext, ListPoliciesQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if uow.lastTenant != tenantID || len(result.Policies) != 1 || result.Policies[0].TenantID != tenantID {
		t.Fatalf("ListPolicies() = %+v, queried tenant = %q", result, uow.lastTenant)
	}
}

func TestQueryEffectivePolicyFallsBackToDefault(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{
		TenantID: tenantID, ID: domainpolicy.DefaultPolicyID, Version: 1, Published: true,
	})
	uow.effectiveError = failure.New(failure.NotFound, "assignment not found")
	service := NewQueryService(uow)

	result, err := service.EffectivePolicy(context.Background(), requestContext, EffectivePolicyQuery{Target: domainpolicy.Target{AgentID: "agent-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.ID != domainpolicy.DefaultPolicyID {
		t.Fatalf("EffectivePolicy() = %+v", result.Policy)
	}
}

func TestQueryEffectivePolicyResolvesAssignmentVersion(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 4, Published: true})
	uow.committed.assignments = []domainpolicy.Assignment{{
		ID: "assignment-a", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"},
		PolicyID: "policy-a", PolicyVersion: 4,
	}}
	service := NewQueryService(uow)

	result, err := service.EffectivePolicy(context.Background(), requestContext, EffectivePolicyQuery{Target: domainpolicy.Target{AgentID: "agent-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.ID != "policy-a" || result.Policy.Version != 4 {
		t.Fatalf("EffectivePolicy() = %+v", result.Policy)
	}
}

func TestSavePolicyCommitsDraftAndAuditTogether(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 1})
	service := NewSaveService(uow, fixedClock{}, &sequenceIDs{"audit-save"})

	result, err := service.Execute(context.Background(), requestContext, SavePolicyCommand{Policy: domainpolicy.Policy{
		TenantID: tenantID, ID: "policy-a", Version: 2, Document: []byte(`{"policy_id":"policy-a"}`),
	}, Reason: "draft"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.Version != 2 || len(uow.committed.policies) != 1 || len(uow.committed.audits) != 1 {
		t.Fatalf("committed state = %+v", uow.committed)
	}
	if uow.committed.audits[0].Action != "policy.upsert" || uow.committed.audits[0].ID != "audit-save" {
		t.Fatalf("audit = %+v", uow.committed.audits[0])
	}
}
