package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestAnalysisRouteDelegatesToApplicationAdapter(t *testing.T) {
	routes := &analysisRoutesStub{}
	server := NewServer(&store.Store{})
	server.SetAnalysisRoutes(routes)
	adminTestHandler(server).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/recompute", nil))
	if routes.calls != 1 {
		t.Fatalf("calls = %d", routes.calls)
	}
}

func TestAnalysisRouteReturnsUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer(&store.Store{})
	recorder := httptest.NewRecorder()
	(&authenticatedTestServer{Server: server, principal: testAdminPrincipal()}).Handler().ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, "/api/v1/recompute", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

type analysisRoutesStub struct{ calls int }

func (stub *analysisRoutesStub) Recompute(http.ResponseWriter, *http.Request) { stub.calls++ }
