package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestNewManagerResponseHTTPRejectsMissingSearcher(t *testing.T) {
	_, err := NewManagerResponseHTTP(new(sql.DB), nil, func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "searcher is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestResponsePreparationResolvesPolicyAndRuntimeScope(t *testing.T) {
	policies := &responsePolicyQueryStub{result: policyapp.EffectivePolicyResult{Policy: domainpolicy.Policy{
		ID: "policy-a", Version: 3,
		Document: []byte(`{"response_policy":{"allowed_actions":["collect"],"allowed_modes":["observe"],"approval_required":true,"approval_threshold":2,"approval_roles":["admin"]}}`),
	}}}
	resolver := responsePreparationResolver{
		policies: policies,
		identity: responseIdentityQueryStub{result: domainidentity.Health{Scope: domainidentity.Scope{Type: "container", Selector: "abc"}}},
	}
	request := managerapp.RequestContext{Actor: tenant.Actor{TenantID: "tenant-a"}}

	result, err := resolver.Resolve(context.Background(), request, domainresponse.Command{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyID != "policy-a" || result.PolicyVersion != 3 || !result.Policy.ApprovalRequired ||
		result.Policy.ApprovalThreshold != 2 || result.Runtime.Type != "container" || result.Runtime.Selector != "abc" || !result.RuntimeKnown {
		t.Fatalf("preparation=%+v", result)
	}
	if policies.target.ScopeType != "container" || policies.target.ScopeSelector != "abc" {
		t.Fatalf("effective policy target=%+v", policies.target)
	}
}

type responsePolicyQueryStub struct {
	result policyapp.EffectivePolicyResult
	target domainpolicy.Target
}

func (stub *responsePolicyQueryStub) EffectivePolicy(_ context.Context, _ managerapp.RequestContext, query policyapp.EffectivePolicyQuery) (policyapp.EffectivePolicyResult, error) {
	stub.target = query.Target
	return stub.result, nil
}

type responseIdentityQueryStub struct{ result domainidentity.Health }

func (stub responseIdentityQueryStub) GetHealth(context.Context, managerapp.RequestContext, domainidentity.AgentID) (domainidentity.Health, error) {
	return stub.result, nil
}
