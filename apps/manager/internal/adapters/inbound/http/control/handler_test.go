package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestCommandsCreatesPublicDocumentFromAuthenticatedActor(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	management := &managementStub{commandResult: domaincontrol.Command{
		ID: "command-a", TenantID: tenantID, AgentID: "agent-a", Type: domaincontrol.CommandTypeContentUpdate,
		Status: domaincontrol.CommandPending, ContentRef: "ioc:test", ContentKind: "iocpack", ContentVersion: "v1",
		Payload: []byte(`{"kind":"iocpack"}`), Actor: "operator-a", CreatedAt: time.Unix(100, 0).UTC(),
	}}
	handler := NewHandler(Options{Management: management, Resolve: operatorResolver(t)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/control-commands", strings.NewReader(`{
		"command_id":"command-a","tenant_id":"tenant-a","agent_id":"agent-a","type":"content_update",
		"payload_json":{"kind":"iocpack"},"actor":"forged","reason":"refresh"
	}`))
	recorder := httptest.NewRecorder()

	handler.Commands(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"command_id":"command-a"`) ||
		!strings.Contains(recorder.Body.String(), `"content_ref":"ioc:test"`) ||
		!strings.Contains(recorder.Body.String(), `"actor":"operator-a"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if management.command.TenantID != "tenant-a" || management.command.CommandID != "command-a" ||
		string(management.command.Payload) != `{"kind":"iocpack"}` {
		t.Fatalf("command = %+v", management.command)
	}
}

func TestEvidenceListsPublicArray(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	query := &queryStub{evidence: []domaincontrol.EvidencePullback{{
		ID: "evidence-a", TenantID: tenantID, AgentID: "agent-a", Status: domaincontrol.EvidencePending,
	}}}
	handler := NewHandler(Options{Query: query, Resolve: operatorResolver(t)})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/evidence-pullbacks?agent_id=agent-a", nil)
	recorder := httptest.NewRecorder()

	handler.Evidence(recorder, request)

	if recorder.Code != http.StatusOK || !strings.HasPrefix(strings.TrimSpace(recorder.Body.String()), "[") ||
		!strings.Contains(recorder.Body.String(), `"request_id":"evidence-a"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCommandsDerivesPolicyIdentityFromPayload(t *testing.T) {
	management := &managementStub{commandResult: domaincontrol.Command{}}
	handler := NewHandler(Options{Management: management, Resolve: operatorResolver(t)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/control-commands", strings.NewReader(`{
		"agent_id":"agent-a","type":"policy_update","payload_json":{"policy_id":"policy-a","version":3}
	}`))
	recorder := httptest.NewRecorder()

	handler.Commands(recorder, request)

	if recorder.Code != http.StatusOK || management.command.PolicyID != "policy-a" || management.command.PolicyVersion != 3 {
		t.Fatalf("status=%d command=%+v body=%s", recorder.Code, management.command, recorder.Body.String())
	}
}

func TestCommandsRejectsEmptyContentPayload(t *testing.T) {
	handler := NewHandler(Options{Management: &managementStub{}, Resolve: operatorResolver(t)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/control-commands", strings.NewReader(`{
		"agent_id":"agent-a","type":"content_update"
	}`))
	recorder := httptest.NewRecorder()

	handler.Commands(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type managementStub struct {
	command       controlapp.CreateCommand
	commandResult domaincontrol.Command
}

func (stub *managementStub) CreateCommand(_ context.Context, _ managerapp.RequestContext, command controlapp.CreateCommand) (domaincontrol.Command, error) {
	stub.command = command
	return stub.commandResult, nil
}

func (stub *managementStub) CreateEvidence(context.Context, managerapp.RequestContext, controlapp.CreateEvidenceCommand) (domaincontrol.EvidencePullback, error) {
	return domaincontrol.EvidencePullback{}, nil
}

func (stub *managementStub) Act(context.Context, managerapp.RequestContext, controlapp.ActionCommand) (domaincontrol.Command, error) {
	return domaincontrol.Command{}, nil
}

type queryStub struct {
	evidence []domaincontrol.EvidencePullback
}

func (stub *queryStub) Commands(context.Context, managerapp.RequestContext, controlapp.CommandQuery) ([]domaincontrol.Command, error) {
	return nil, nil
}

func (stub *queryStub) Evidence(context.Context, managerapp.RequestContext, controlapp.EvidenceQuery) ([]domaincontrol.EvidencePullback, error) {
	return stub.evidence, nil
}

func operatorResolver(t *testing.T) RequestContextResolver {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{
			Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
		}}, nil
	}
}
