package status

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerPreservesHealthAndStoreStatusJSON(t *testing.T) {
	handler := NewHandler(StorageStatus{Backend: "postgres", StateVersion: 1,
		MigrationVersion: 1, PostgresSchemaVersion: 9})

	health := httptest.NewRecorder()
	handler.Health(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for _, want := range []string{`"ok":true`, `"store"`, `"backend":"postgres"`, `"postgres_schema_version":9`} {
		if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), want) {
			t.Fatalf("health missing %s: status=%d body=%s", want, health.Code, health.Body.String())
		}
	}

	store := httptest.NewRecorder()
	handler.StoreStatus(store, httptest.NewRequest(http.MethodGet, "/api/v1/store-status", nil))
	for _, want := range []string{`"backend":"postgres"`, `"state_version":1`, `"migration_version":1`, `"postgres_schema_version":9`} {
		if store.Code != http.StatusOK || !strings.Contains(store.Body.String(), want) {
			t.Fatalf("store status missing %s: status=%d body=%s", want, store.Code, store.Body.String())
		}
	}
}

func TestStoreStatusRejectsNonGET(t *testing.T) {
	handler := NewHandler(StorageStatus{})
	recorder := httptest.NewRecorder()
	handler.StoreStatus(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/store-status", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
