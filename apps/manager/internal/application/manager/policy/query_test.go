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

func TestQueryRulesUsesActorTenantAndWhereFilter(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{})
	uow.committed.rules = []domainpolicy.Rule{{TenantID: tenantID, Where: "cloud", Document: []byte(`{"rule_id":"cloud-a"}`)}}
	service := NewQueryService(uow)

	rules, err := service.ListRules(context.Background(), requestContext, domainpolicy.RuleFilter{Where: "cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if uow.lastTenant != tenantID || uow.lastRuleWhere != "cloud" || len(rules) != 1 || rules[0].TenantID != tenantID {
		t.Fatalf("rules=%+v tenant=%q where=%q", rules, uow.lastTenant, uow.lastRuleWhere)
	}
}

func TestQueryPolicyGetsRequestedVersion(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 3})
	service := NewQueryService(uow)

	result, err := service.GetPolicy(context.Background(), requestContext, GetPolicyQuery{PolicyID: "policy-a", Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.ID != "policy-a" || result.Policy.Version != 3 || uow.lastTenant != tenantID {
		t.Fatalf("GetPolicy() = %+v, queried tenant = %q", result, uow.lastTenant)
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

func TestQueryEffectivePolicySkipsUnpublishedAssignmentPolicy(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{
		TenantID: tenantID, ID: "policy-a", Version: 2, Published: false,
	})
	uow.committed.assignments = []domainpolicy.Assignment{{
		ID: "assignment-a", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"},
		PolicyID: "policy-a", PolicyVersion: 2,
	}}
	uow.defaultPolicy = domainpolicy.Policy{
		TenantID: tenantID, ID: domainpolicy.DefaultPolicyID, Version: 1, Published: true,
	}
	service := NewQueryService(uow)

	result, err := service.EffectivePolicy(context.Background(), requestContext, EffectivePolicyQuery{Target: domainpolicy.Target{AgentID: "agent-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.ID != domainpolicy.DefaultPolicyID || !result.Policy.Published {
		t.Fatalf("EffectivePolicy() = %+v", result.Policy)
	}
}

func TestQueryEffectivePolicyFallsThroughUnpublishedHigherPriorityAssignment(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{
		TenantID: tenantID, ID: "agent-policy", Version: 2, Published: false,
	})
	uow.policyByID = map[domainpolicy.ID]domainpolicy.Policy{
		"agent-policy": {TenantID: tenantID, ID: "agent-policy", Version: 2, Published: false},
		"scope-policy": {TenantID: tenantID, ID: "scope-policy", Version: 1, Published: true},
	}
	uow.committed.assignments = []domainpolicy.Assignment{
		{ID: "agent", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"}, PolicyID: "agent-policy", PolicyVersion: 2},
		{ID: "scope", TenantID: tenantID, Target: domainpolicy.Target{ScopeType: "host", ScopeSelector: "prod"}, PolicyID: "scope-policy", PolicyVersion: 1},
	}
	service := NewQueryService(uow)

	result, err := service.EffectivePolicy(context.Background(), requestContext, EffectivePolicyQuery{Target: domainpolicy.Target{
		AgentID: "agent-a", ScopeType: "host", ScopeSelector: "prod",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.ID != "scope-policy" {
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
