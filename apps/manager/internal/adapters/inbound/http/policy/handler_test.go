package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestPublishMapsRequestContextAndCanonicalResult(t *testing.T) {
	tenantID := mustHTTPPolicyTenant(t)
	useCase := &publishRecorder{result: policyapp.PublishPolicyResult{Policy: domainpolicy.Policy{
		TenantID: tenantID, ID: "policy-a", Version: 2, Published: true,
		Document: []byte(`{"tenant_id":"other","policy_id":"other","version":99,"published":false}`),
	}}}
	handler := NewHandler(Options{Publish: useCase, Resolve: fixedResolver(t, tenantID)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-publish", strings.NewReader(
		`{"tenant_id":"tenant-a","policy_id":"policy-a","version":2,"published":true,"reason":"ready"}`,
	))
	rec := httptest.NewRecorder()

	handler.Publish(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if useCase.request.Actor.TenantID != tenantID || useCase.command.PolicyID != "policy-a" || !useCase.command.Published {
		t.Fatalf("mapped request = %+v, command = %+v", useCase.request, useCase.command)
	}
	for _, want := range []string{`"tenant_id":"tenant-a"`, `"policy_id":"policy-a"`, `"version":2`, `"published":true`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("response %s missing %s", rec.Body.String(), want)
		}
	}
}

func TestAssignMapsDownlinkTarget(t *testing.T) {
	tenantID := mustHTTPPolicyTenant(t)
	useCase := &assignRecorder{result: policyapp.AssignPolicyResult{Assignment: domainpolicy.Assignment{
		ID: "assignment-a", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"},
		PolicyID: "policy-a", PolicyVersion: 2,
	}}}
	handler := NewHandler(Options{Assign: useCase, Resolve: fixedResolver(t, tenantID)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(
		`{"tenant_id":"tenant-a","assignment_id":"requested-assignment","agent_id":"agent-a","policy_id":"policy-a","policy_version":2,"downlink":true,"command_id":"command-a"}`,
	))
	rec := httptest.NewRecorder()

	handler.Assignments(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if useCase.command.AssignmentID != "requested-assignment" || useCase.command.Target.AgentID != "agent-a" || !useCase.command.Downlink || useCase.command.CommandID != "command-a" {
		t.Fatalf("mapped command = %+v", useCase.command)
	}
}

type publishRecorder struct {
	request managerapp.RequestContext
	command policyapp.PublishPolicyCommand
	result  policyapp.PublishPolicyResult
}

func (recorder *publishRecorder) Execute(_ context.Context, request managerapp.RequestContext, command policyapp.PublishPolicyCommand) (policyapp.PublishPolicyResult, error) {
	recorder.request, recorder.command = request, command
	return recorder.result, nil
}

type assignRecorder struct {
	command policyapp.AssignPolicyCommand
	result  policyapp.AssignPolicyResult
}

func (recorder *assignRecorder) Execute(_ context.Context, _ managerapp.RequestContext, command policyapp.AssignPolicyCommand) (policyapp.AssignPolicyResult, error) {
	recorder.command = command
	return recorder.result, nil
}

func fixedResolver(t *testing.T, tenantID tenant.ID) RequestContextResolver {
	t.Helper()
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{
			Subject: "admin-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin),
		}}, nil
	}
}

func mustHTTPPolicyTenant(t *testing.T) tenant.ID {
	t.Helper()
	id, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
