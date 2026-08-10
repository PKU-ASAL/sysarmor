package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
)

func TestTelemetryRoutesDelegateToApplicationAdapter(t *testing.T) {
	routes := &telemetryRoutesStub{}
	server := NewServer()
	server.SetTelemetryRoutes(routes)
	handler := adminTestHandler(server)
	for _, path := range []string{"/api/v1/events", "/api/v1/signals", "/api/v1/incidents"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if routes.events != 1 || routes.signals != 1 || routes.incidents != 1 {
		t.Fatalf("events=%d signals=%d incidents=%d", routes.events, routes.signals, routes.incidents)
	}
}

func TestTelemetryRoutesReturnUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer()
	handler := (&authenticatedTestServer{Server: server, principal: testAdminPrincipal()}).Handler()
	for _, path := range []string{"/api/v1/events", "/api/v1/signals", "/api/v1/incidents"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func testAdminPrincipal() managerauth.Principal {
	return managerauth.Principal{Subject: "test-admin", TenantID: "default", Roles: []string{"admin"}}
}

type telemetryRoutesStub struct{ events, signals, incidents int }

func (stub *telemetryRoutesStub) Events(http.ResponseWriter, *http.Request)    { stub.events++ }
func (stub *telemetryRoutesStub) Signals(http.ResponseWriter, *http.Request)   { stub.signals++ }
func (stub *telemetryRoutesStub) Incidents(http.ResponseWriter, *http.Request) { stub.incidents++ }
