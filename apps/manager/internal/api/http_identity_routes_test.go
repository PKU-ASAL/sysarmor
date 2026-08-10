package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentityEndpointsReturnUnavailableWithoutAdapter(t *testing.T) {
	handler := adminTestHandler(NewServer())
	requests := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents"}, {http.MethodGet, "/api/v1/agent-health"},
		{http.MethodPost, "/api/v1/agent-health"}, {http.MethodGet, "/api/v1/agent-sessions"},
		{http.MethodGet, "/api/v1/data-resume"}, {http.MethodGet, "/api/v1/metrics"},
		{http.MethodGet, "/api/v1/rarity-baseline"},
	}
	for _, request := range requests {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(request.method, request.path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("method=%s path=%s status=%d body=%s", request.method, request.path, recorder.Code, recorder.Body.String())
		}
	}
}
