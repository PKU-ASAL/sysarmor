package managerapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/auth"
)

func TestIncidentMutationRoutesAreNotRegistered(t *testing.T) {
	handler := NewServer().Handler()
	for _, path := range []string{
		"/api/v1/incident-lifecycle",
		"/api/v1/incident-merge",
		"/api/v1/incident-evidence",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req = withTestPrincipal(req, "test-admin", "default", "admin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("POST %s status = %d, want 404", path, rec.Code)
		}
	}
}

func TestIncidentReportsRequireSearchBackend(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?tenant_id=default", nil)
	rec := httptest.NewRecorder()
	req = req.WithContext(managerauth.WithPrincipal(req.Context(), managerauth.Principal{Subject: "viewer", TenantID: "default", Roles: []string{"viewer"}}))
	newServer(nil).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
