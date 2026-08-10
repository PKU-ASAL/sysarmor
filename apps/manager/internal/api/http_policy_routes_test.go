package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyEndpointsDelegateToInjectedRoutes(t *testing.T) {
	routes := &recordingPolicyRoutes{}
	server := NewServer()
	server.SetPolicyRoutes(routes)
	handler := adminTestHandler(server)

	for _, path := range []string{
		"/api/v1/rules",
		"/api/v1/policies", "/api/v1/policy-publish", "/api/v1/policy-audit",
		"/api/v1/policy-assignments", "/api/v1/effective-policy", "/api/v1/policy-rollouts",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	}
	if routes.calls != 7 {
		t.Fatalf("delegated calls = %d, want 7", routes.calls)
	}
}

func TestPolicyEndpointsReturnUnavailableWithoutAdapter(t *testing.T) {
	server := NewServer()
	handler := adminTestHandler(server)
	for _, path := range []string{"/api/v1/rules", "/api/v1/policies", "/api/v1/policy-publish",
		"/api/v1/policy-audit", "/api/v1/policy-assignments", "/api/v1/effective-policy", "/api/v1/policy-rollouts"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

type recordingPolicyRoutes struct{ calls int }

func (routes *recordingPolicyRoutes) Policies(http.ResponseWriter, *http.Request)    { routes.calls++ }
func (routes *recordingPolicyRoutes) Rules(http.ResponseWriter, *http.Request)       { routes.calls++ }
func (routes *recordingPolicyRoutes) Publish(http.ResponseWriter, *http.Request)     { routes.calls++ }
func (routes *recordingPolicyRoutes) Audits(http.ResponseWriter, *http.Request)      { routes.calls++ }
func (routes *recordingPolicyRoutes) Assignments(http.ResponseWriter, *http.Request) { routes.calls++ }
func (routes *recordingPolicyRoutes) Effective(http.ResponseWriter, *http.Request)   { routes.calls++ }
func (routes *recordingPolicyRoutes) Rollouts(http.ResponseWriter, *http.Request)    { routes.calls++ }
