package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollmentRoutesHandleEveryEnrollmentEndpoint(t *testing.T) {
	server := NewServer()
	server.SetEnrollmentRoutes(enrollmentRoutesStub{})
	handler := adminTestHandler(server)
	for _, endpoint := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/enrollments"},
		{http.MethodGet, "/api/v1/agent-install.sh"},
		{http.MethodGet, "/api/v1/enrollment-artifact"},
		{http.MethodPost, "/api/v1/enrollment-certificate"},
		{http.MethodPost, "/api/v1/unenrollment-completions"},
		{http.MethodGet, "/api/v1/ui/deploy/options"},
		{http.MethodPost, "/api/v1/ui/deploy/agent-command"},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusTeapot {
				t.Fatalf("status = %d", recorder.Code)
			}
		})
	}
}

type enrollmentRoutesStub struct{}

func (enrollmentRoutesStub) Enrollments(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) Install(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) Artifact(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) DeployOptions(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) DeployAgentCommand(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) Certificate(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}

func (enrollmentRoutesStub) Completion(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}
