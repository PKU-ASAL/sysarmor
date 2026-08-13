package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

func TestRolloutsPreservePublicJSONAndFilters(t *testing.T) {
	tenantID := mustHTTPPolicyTenant(t)
	queries := &rolloutQueryRecorder{result: []policyapp.Rollout{{
		TenantID: tenantID, AgentID: "agent-a", Status: "pending", DesiredPolicyID: "policy-a",
		DesiredPolicyVersion: 3, AppliedPolicyID: "old-policy", AppliedPolicyVersion: 1,
		PendingPolicy: domainidentity.PendingPolicy{Status: "pending", ID: "policy-a", Version: 3}, Drift: true,
	}}}
	handler := NewHandler(Options{Rollout: queries, Resolve: fixedResolver(t, tenantID)})
	recorder := httptest.NewRecorder()
	handler.Rollouts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/policy-rollouts?tenant_id=other&agent_id=agent-a&status=pending", nil))

	if recorder.Code != http.StatusOK || queries.request.Actor.TenantID != tenantID || queries.query.AgentID != "agent-a" || queries.query.Status != "pending" {
		t.Fatalf("status=%d request=%+v query=%+v body=%s", recorder.Code, queries.request, queries.query, recorder.Body.String())
	}
	for _, field := range []string{`"tenant_id":"tenant-a"`, `"desired_policy_version":3`, `"pending_policy"`, `"drift":true`} {
		if !strings.Contains(recorder.Body.String(), field) {
			t.Fatalf("response missing %s: %s", field, recorder.Body.String())
		}
	}
}

func TestRolloutDocumentPreservesZeroTimeKeys(t *testing.T) {
	document := rolloutDocument(policyapp.Rollout{})
	for _, key := range []string{"last_dispatch_at", "last_ack_at", "health_observed_at", "pending_policy"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("rollout document missing %q: %+v", key, document)
		}
	}
}

func TestRolloutsHideDependencyErrors(t *testing.T) {
	tenantID := mustHTTPPolicyTenant(t)
	handler := NewHandler(Options{Rollout: &rolloutQueryRecorder{err: errors.New("database password leaked")}, Resolve: fixedResolver(t, tenantID)})
	recorder := httptest.NewRecorder()
	handler.Rollouts(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/policy-rollouts", nil))
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "read policy rollout state\n" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

type rolloutQueryRecorder struct {
	request managerapp.RequestContext
	query   policyapp.RolloutQuery
	result  []policyapp.Rollout
	err     error
}

func (recorder *rolloutQueryRecorder) List(_ context.Context, request managerapp.RequestContext, query policyapp.RolloutQuery) ([]policyapp.Rollout, error) {
	recorder.request, recorder.query = request, query
	return recorder.result, recorder.err
}
