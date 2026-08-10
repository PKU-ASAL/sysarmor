package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
)

func TestSearchRoutesDelegateToApplicationAdapter(t *testing.T) {
	routes := &searchRoutesStub{}
	server := NewServer()
	server.SetSearchRoutes(routes)
	handler := adminTestHandler(server)
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/search/fields"},
		{http.MethodPost, "/api/v1/search"},
		{http.MethodPost, "/api/v1/search/histogram"},
	} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(endpoint.method, endpoint.path, nil))
	}
	if routes.fields != 1 || routes.search != 1 || routes.histogram != 1 {
		t.Fatalf("fields=%d search=%d histogram=%d", routes.fields, routes.search, routes.histogram)
	}
}

func TestSearchRoutesReturnUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer()
	handler := (&authenticatedTestServer{Server: server, principal: managerauth.Principal{
		Subject: "admin-a", TenantID: "default", Roles: []string{"admin"},
	}}).Handler()
	for _, path := range []string{"/api/v1/search/fields", "/api/v1/search", "/api/v1/search/histogram"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

type searchRoutesStub struct{ fields, search, histogram int }

func (stub *searchRoutesStub) Fields(http.ResponseWriter, *http.Request)    { stub.fields++ }
func (stub *searchRoutesStub) Search(http.ResponseWriter, *http.Request)    { stub.search++ }
func (stub *searchRoutesStub) Histogram(http.ResponseWriter, *http.Request) { stub.histogram++ }
