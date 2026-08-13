package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

func TestNewManagerAnalysisHTTPRequiresDependencies(t *testing.T) {
	resolver := func(*http.Request) (managerapp.RequestContext, error) { return managerapp.RequestContext{}, nil }
	if _, err := NewManagerAnalysisHTTP(nil, telemetryBootstrapSearcher{}, resolver); err == nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("database error = %v", err)
	}
	if _, err := NewManagerAnalysisHTTP(new(sql.DB), nil, resolver); err == nil || !strings.Contains(err.Error(), "searcher") {
		t.Fatalf("searcher error = %v", err)
	}
	if _, err := NewManagerAnalysisHTTP(new(sql.DB), telemetryBootstrapSearcher{}, nil); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("resolver error = %v", err)
	}
}

func TestManagerAnalysisPolicyMapsEffectiveDocument(t *testing.T) {
	query := &effectivePolicyStub{result: policyapp.EffectivePolicyResult{Policy: domainpolicy.Policy{
		Document: []byte(`{"cloud_rules":["web_shell_chain"],"converge":{"cross_lineage":true}}`),
	}}}
	policy, err := (managerAnalysisPolicy{queries: query}).Effective(context.Background(), managerapp.RequestContext{}, domainpolicy.Target{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.CloudRules[0] != "web_shell_chain" || policy.Converge == nil || !policy.Converge.CrossLineage || query.target.AgentID != "agent-a" {
		t.Fatalf("policy = %+v, target = %+v", policy, query.target)
	}
}

type effectivePolicyStub struct {
	target domainpolicy.Target
	result policyapp.EffectivePolicyResult
}

func (stub *effectivePolicyStub) EffectivePolicy(_ context.Context, _ managerapp.RequestContext, query policyapp.EffectivePolicyQuery) (policyapp.EffectivePolicyResult, error) {
	stub.target = query.Target
	return stub.result, nil
}
