package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestOverviewRouteDelegatesToApplicationAdapter(t *testing.T) {
	routes := &overviewRoutesStub{}
	server := NewServer(&store.Store{})
	server.SetOverviewRoutes(routes)
	handler := adminTestHandler(server)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview", nil))
	if routes.calls != 1 {
		t.Fatalf("overview calls=%d", routes.calls)
	}
}

func TestOverviewRouteReturnsUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer(&store.Store{})
	recorder := httptest.NewRecorder()
	adminTestHandler(server).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ui/overview", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type overviewRoutesStub struct{ calls int }

func (stub *overviewRoutesStub) Overview(http.ResponseWriter, *http.Request) { stub.calls++ }
