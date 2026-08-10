package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestEnrollmentRoutesOverrideLegacyCertificateHandler(t *testing.T) {
	server := NewServer(&store.Store{})
	routes := enrollmentRoutesStub{}
	server.SetEnrollmentRoutes(routes)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-certificate", nil)

	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status = %d", recorder.Code)
	}
}

type enrollmentRoutesStub struct{}

func (enrollmentRoutesStub) Certificate(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusTeapot)
}
