package response

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestResponsesCreateDelegatesAuthenticatedContext(t *testing.T) {
	service := &responseServiceStub{createResult: domainresponse.PrepareResult{Allowed: true, Command: domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "collect", Mode: "observe",
		Status: domainresponse.StatusPending, Actor: "operator-a",
	}}}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/responses", strings.NewReader(
		`{"tenant_id":"tenant-b","agent_id":"agent-a","action":"collect","actor":"forged"}`))

	handler.Responses(recorder, request)
	if recorder.Code != http.StatusOK || service.create.Actor != "" || service.request.Actor.Subject != "operator-a" {
		t.Fatalf("status=%d body=%s create=%+v request=%+v", recorder.Code, recorder.Body.String(), service.create, service.request)
	}
	for _, want := range []string{`"response_id":"response-a"`, `"tenant_id":"tenant-a"`, `"actor":"operator-a"`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("body missing %s: %s", want, recorder.Body.String())
		}
	}
}

func TestResponsesPendingReturnsCommandDocuments(t *testing.T) {
	service := &responseServiceStub{listed: []domainresponse.Command{{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "collect", Status: domainresponse.StatusPending,
	}}}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Responses(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/responses?pending=true&agent_id=agent-a", nil))

	if recorder.Code != http.StatusOK || !service.query.Pending || !strings.Contains(recorder.Body.String(), `"response_id":"response-a"`) ||
		strings.Contains(recorder.Body.String(), `"command"`) {
		t.Fatalf("status=%d body=%s query=%+v", recorder.Code, recorder.Body.String(), service.query)
	}
}

func TestApprovalsHideIneligibleCommandsAsNotFound(t *testing.T) {
	tests := []struct {
		name string
		kind failure.Kind
	}{
		{name: "role is not allowed", kind: failure.PermissionDenied},
		{name: "command is not awaiting approval", kind: failure.FailedPrecondition},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &responseServiceStub{approveErr: failure.New(test.kind, test.name)}
			handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/response-approvals", strings.NewReader(
				`{"response_id":"response-a","agent_id":"agent-a","approved":true}`))

			handler.Approvals(recorder, request)

			if recorder.Code != http.StatusNotFound || recorder.Body.String() != "response command not found\n" {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestApprovalsUseAuthenticatedRole(t *testing.T) {
	service := &responseServiceStub{}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/response-approvals", strings.NewReader(
		`{"response_id":"response-a","agent_id":"agent-a","approved":true,"actor":"forged","role":"admin"}`))

	handler.Approvals(recorder, request)

	if recorder.Code != http.StatusOK || service.approval.Role != string(tenant.RoleOperator) ||
		service.request.Actor.Subject != "operator-a" {
		t.Fatalf("status=%d approval=%+v request=%+v", recorder.Code, service.approval, service.request)
	}
}

func TestAcknowledgementsUseAuthenticatedTenant(t *testing.T) {
	service := &responseServiceStub{}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/response-acks", strings.NewReader(
		`{"response_id":"response-a","tenant_id":"tenant-b","agent_id":"agent-a","accepted":true}`))

	handler.Acknowledgements(recorder, request)

	if recorder.Code != http.StatusOK || service.acknowledgement.TenantID != "tenant-a" {
		t.Fatalf("status=%d acknowledgement=%+v", recorder.Code, service.acknowledgement)
	}
}

func TestAcknowledgementsRequireAgentID(t *testing.T) {
	service := &responseServiceStub{}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/response-acks", strings.NewReader(
		`{"response_id":"response-a","accepted":true}`))

	handler.Acknowledgements(recorder, request)

	if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "agent_id is required\n" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestResponsesDenialReturnsAuditDocument(t *testing.T) {
	service := &responseServiceStub{createResult: domainresponse.PrepareResult{Command: domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domainresponse.StatusDenied,
	}}}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/responses", strings.NewReader(`{"agent_id":"agent-a"}`))

	handler.Responses(recorder, request)

	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"command"`) ||
		!strings.Contains(recorder.Body.String(), `"status":"denied"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestResponsesListReturnsAuditDocuments(t *testing.T) {
	ack := domainresponse.Acknowledgement{TenantID: "tenant-a", AgentID: "agent-a", Accepted: true}
	service := &responseServiceStub{listed: []domainresponse.Command{{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domainresponse.StatusAcknowledged, Ack: &ack,
	}}}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()

	handler.Responses(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/responses", nil))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"command"`) ||
		!strings.Contains(recorder.Body.String(), `"ack"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApprovalsReturnAuditDocument(t *testing.T) {
	service := &responseServiceStub{approveResult: domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domainresponse.StatusPending,
	}}
	handler := NewHandler(Options{Service: service, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/response-approvals", strings.NewReader(
		`{"response_id":"response-a","agent_id":"agent-a","approved":true}`))

	handler.Approvals(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"command"`) ||
		!strings.Contains(recorder.Body.String(), `"response_id":"response-a"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAcknowledgementsReturnOKDocument(t *testing.T) {
	handler := NewHandler(Options{Service: &responseServiceStub{}, Resolve: responseRequestResolver(t)})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/response-acks", strings.NewReader(
		`{"response_id":"response-a","agent_id":"agent-a","accepted":true}`))

	handler.Acknowledgements(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"ok\":true}\n" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestResponseEndpointsRejectUnsupportedMethods(t *testing.T) {
	handler := NewHandler(Options{})
	tests := []struct {
		path   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{path: "/api/v1/responses", handle: handler.Responses},
		{path: "/api/v1/response-decisions", handle: handler.Decisions},
		{path: "/api/v1/response-approvals", handle: handler.Approvals},
		{path: "/api/v1/response-acks", handle: handler.Acknowledgements},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		test.handle(recorder, httptest.NewRequest(http.MethodDelete, test.path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("path=%s status=%d", test.path, recorder.Code)
		}
	}
}

type responseServiceStub struct {
	request         managerapp.RequestContext
	create          domainresponse.Command
	createResult    domainresponse.PrepareResult
	decisionResult  domainresponse.PrepareResult
	approval        responseapp.ApprovalCommand
	approveResult   domainresponse.Command
	acknowledgement responseapp.AcknowledgeCommand
	query           responseapp.Query
	listed          []domainresponse.Command
	approveErr      error
}

func (stub *responseServiceStub) Create(_ context.Context, request managerapp.RequestContext, command domainresponse.Command) (domainresponse.PrepareResult, error) {
	stub.request, stub.create = request, command
	return stub.createResult, nil
}

func (stub *responseServiceStub) Decide(context.Context, managerapp.RequestContext, responseapp.DecisionCommand) (domainresponse.PrepareResult, error) {
	return stub.decisionResult, nil
}

func (stub *responseServiceStub) Approve(_ context.Context, request managerapp.RequestContext, command responseapp.ApprovalCommand) (domainresponse.Command, error) {
	stub.request, stub.approval = request, command
	return stub.approveResult, stub.approveErr
}

func (stub *responseServiceStub) Acknowledge(_ context.Context, command responseapp.AcknowledgeCommand) (domainresponse.Acknowledged, error) {
	stub.acknowledgement = command
	return domainresponse.Acknowledged{}, nil
}

func (stub *responseServiceStub) List(_ context.Context, request managerapp.RequestContext, query responseapp.Query) ([]domainresponse.Command, error) {
	stub.request, stub.query = request, query
	return stub.listed, nil
}

func responseRequestResolver(t *testing.T) RequestContextResolver {
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
