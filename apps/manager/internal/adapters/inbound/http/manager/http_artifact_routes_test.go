package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestArtifactRoutesDelegateToApplicationAdapter(t *testing.T) {
	routes := &artifactRoutesStub{}
	server := NewServer()
	server.SetArtifactRoutes(routes)
	handler := adminTestHandler(server)

	for _, endpoint := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/artifacts"},
		{http.MethodGet, "/api/v1/artifacts/artifact-a"},
		{http.MethodGet, "/api/v1/channels"},
	} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(endpoint.method, endpoint.path, nil))
	}
	if routes.artifacts != 1 || routes.artifact != 1 || routes.channels != 1 {
		t.Fatalf("artifacts=%d artifact=%d channels=%d", routes.artifacts, routes.artifact, routes.channels)
	}
}

func TestArtifactRoutesReturnUnavailableWithoutAdapter(t *testing.T) {
	handler := adminTestHandler(NewServer())
	for _, path := range []string{"/api/v1/artifacts", "/api/v1/artifacts/artifact-a", "/api/v1/channels"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

type artifactRoutesStub struct{ artifacts, artifact, channels int }

func (stub *artifactRoutesStub) Artifacts(http.ResponseWriter, *http.Request) { stub.artifacts++ }
func (stub *artifactRoutesStub) Artifact(http.ResponseWriter, *http.Request)  { stub.artifact++ }
func (stub *artifactRoutesStub) Channels(http.ResponseWriter, *http.Request)  { stub.channels++ }
