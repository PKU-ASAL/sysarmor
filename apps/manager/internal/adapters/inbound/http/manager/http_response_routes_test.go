package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseRoutesDelegateToApplicationAdapter(t *testing.T) {
	routes := &responseRoutesStub{}
	server := NewServer()
	server.SetResponseRoutes(routes)
	handler := adminTestHandler(server)

	for _, path := range []string{"/api/v1/responses", "/api/v1/response-decisions", "/api/v1/response-approvals", "/api/v1/response-acks"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
	}
	if routes.responses != 1 || routes.decisions != 1 || routes.approvals != 1 || routes.acks != 1 {
		t.Fatalf("responses=%d decisions=%d approvals=%d acks=%d", routes.responses, routes.decisions, routes.approvals, routes.acks)
	}
}

type responseRoutesStub struct{ responses, decisions, approvals, acks int }

func (stub *responseRoutesStub) Responses(http.ResponseWriter, *http.Request)        { stub.responses++ }
func (stub *responseRoutesStub) Decisions(http.ResponseWriter, *http.Request)        { stub.decisions++ }
func (stub *responseRoutesStub) Approvals(http.ResponseWriter, *http.Request)        { stub.approvals++ }
func (stub *responseRoutesStub) Acknowledgements(http.ResponseWriter, *http.Request) { stub.acks++ }
