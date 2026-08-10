package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestStatusRoutesDelegateToInjectedAdapter(t *testing.T) {
	routes := &statusRoutesStub{}
	server := NewServer(&store.Store{})
	server.SetStatusRoutes(routes)
	server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	adminTestHandler(server).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/store-status", nil))
	if routes.health != 1 || routes.store != 1 {
		t.Fatalf("health=%d store=%d", routes.health, routes.store)
	}
}

func TestStatusRoutesReturnUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer(&store.Store{})
	for _, handler := range []struct {
		path    string
		handler http.Handler
	}{
		{path: "/healthz", handler: server.Handler()},
		{path: "/api/v1/store-status", handler: adminTestHandler(server)},
	} {
		recorder := httptest.NewRecorder()
		handler.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, handler.path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", handler.path, recorder.Code, recorder.Body.String())
		}
	}
}

type statusRoutesStub struct{ health, store int }

func (stub *statusRoutesStub) Health(http.ResponseWriter, *http.Request)      { stub.health++ }
func (stub *statusRoutesStub) StoreStatus(http.ResponseWriter, *http.Request) { stub.store++ }
