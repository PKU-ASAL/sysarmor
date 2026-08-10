package managerapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestPolicyPublishPersistenceFailureReturnsInternalServerError(t *testing.T) {
	st := &store.Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1}}}
	handler := newAdminTestServer(st).Handler()
	st.AttachBackend(context.Background(), httpFailingBackend{operation: "policy"}, store.Info{Backend: "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-publish", strings.NewReader(`{"tenant_id":"default","policy_id":"policy-fail","version":1,"published":true}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError || st.Policies[0].Published || len(st.PolicyAudits) != 0 {
		t.Fatalf("policy publish status=%d body=%q policy=%+v audits=%+v", rec.Code, rec.Body.String(), st.Policies[0], st.PolicyAudits)
	}
}

func TestPolicyAssignmentPersistenceFailureReturnsInternalServerError(t *testing.T) {
	st := &store.Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1, Published: true}}}
	handler := newAdminTestServer(st).Handler()
	st.AttachBackend(context.Background(), httpFailingBackend{operation: "assignment"}, store.Info{Backend: "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(`{"tenant_id":"default","agent_id":"agent-a","policy_id":"policy-fail","policy_version":1,"downlink":true,"command_id":"control-fail"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError || len(st.Assignments) != 0 || len(st.PolicyAudits) != 0 || len(st.ControlCommands) != 0 {
		t.Fatalf("policy assignment status=%d body=%q assignments=%+v audits=%+v commands=%+v", rec.Code, rec.Body.String(), st.Assignments, st.PolicyAudits, st.ControlCommands)
	}
}

func TestPolicyAssignmentConflictReturnsConflict(t *testing.T) {
	st := &store.Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-conflict", Version: 1, Published: true}}}
	handler := newAdminTestServer(st).Handler()
	st.AttachBackend(context.Background(), httpFailingBackend{operation: "assignment_conflict"}, store.Info{Backend: "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(`{"tenant_id":"default","agent_id":"agent-a","policy_id":"policy-conflict","policy_version":1,"downlink":true,"command_id":"control-conflict"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("policy assignment status=%d body=%q, want 409", rec.Code, rec.Body.String())
	}
}

type httpFailingBackend struct {
	store.Backend
	operation string
}

func (b httpFailingBackend) ListArtifacts(context.Context, string, string, string) ([]store.Artifact, error) {
	return nil, b.failure("security_read")
}

func (b httpFailingBackend) ListChannels(context.Context, string) ([]store.ArtifactChannel, error) {
	return nil, b.failure("security_read")
}

func (b httpFailingBackend) ListAgents(context.Context) ([]store.AgentIdentity, error) {
	return nil, b.failure("rollout")
}

func (b httpFailingBackend) WriteControlCommand(context.Context, controlmodel.ControlCommand) error {
	return b.failure("control")
}

func (b httpFailingBackend) CreateControlCommand(context.Context, controlmodel.ControlCommand) (bool, error) {
	return false, b.failure("control")
}

func (httpFailingBackend) ListControlCommands(context.Context, string, string, string) ([]controlmodel.ControlCommand, error) {
	return nil, nil
}

func (httpFailingBackend) GetPolicy(context.Context, string, string, uint64) (policymodel.Policy, bool, error) {
	return policymodel.Policy{}, false, nil
}

func (httpFailingBackend) ListAssignments(context.Context, string, string) ([]policymodel.Assignment, error) {
	return nil, nil
}

func (b httpFailingBackend) WritePolicy(context.Context, policymodel.Policy) error {
	return b.failure("policy")
}

func (b httpFailingBackend) WriteAssignment(context.Context, policymodel.Assignment) error {
	return b.failure("assignment")
}

func (b httpFailingBackend) CommitPolicyPublication(context.Context, policymodel.Policy, policymodel.AuditRecord) error {
	return b.failure("policy")
}

func (b httpFailingBackend) CommitPolicyAssignment(context.Context, policymodel.Assignment, policymodel.AuditRecord, *controlmodel.ControlCommand) (*controlmodel.ControlCommand, error) {
	if b.operation == "assignment_conflict" {
		return nil, store.ErrConflict
	}
	return nil, b.failure("assignment")
}

func (httpFailingBackend) GetAgentHealth(context.Context, string, string) (agenthealth.AgentHealth, bool, error) {
	return agenthealth.AgentHealth{}, false, nil
}

func (httpFailingBackend) EffectivePolicy(context.Context, string, string, string, string) (policymodel.Policy, bool, error) {
	return policymodel.Policy{}, false, nil
}

func (b httpFailingBackend) failure(operation string) error {
	if b.operation == operation {
		return errors.New("backend down")
	}
	return nil
}
