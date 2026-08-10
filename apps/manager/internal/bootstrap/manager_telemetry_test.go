package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestNewManagerTelemetryHTTPRequiresDependencies(t *testing.T) {
	if _, err := NewManagerTelemetryHTTP(nil, func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{}, nil
	}); err == nil || !strings.Contains(err.Error(), "searcher") {
		t.Fatalf("searcher error=%v", err)
	}
	if _, err := NewManagerTelemetryHTTP(telemetryBootstrapSearcher{}, nil); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("resolver error=%v", err)
	}
}

func TestNewManagerTelemetryQueriesRequiresSearcher(t *testing.T) {
	if _, err := NewManagerTelemetryQueries(nil); err == nil || !strings.Contains(err.Error(), "searcher") {
		t.Fatalf("searcher error=%v", err)
	}
	queries, err := NewManagerTelemetryQueries(telemetryBootstrapSearcher{})
	if err != nil || queries == nil {
		t.Fatalf("queries=%v error=%v", queries, err)
	}
}

func TestNewManagerTelemetryHTTPWiresQuery(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	handler, err := NewManagerTelemetryHTTP(telemetryBootstrapSearcher{}, func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
			Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.Events(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[{\"id\":\"event-a\",\"tenant_id\":\"tenant-a\"}]\n" {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestNewManagerSearchHTTPRequiresDependencies(t *testing.T) {
	if _, err := NewManagerSearchHTTP(nil, func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{}, nil
	}); err == nil || !strings.Contains(err.Error(), "searcher") {
		t.Fatalf("searcher error=%v", err)
	}
	if _, err := NewManagerSearchHTTP(telemetryBootstrapSearcher{}, nil); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("resolver error=%v", err)
	}
}

type telemetryBootstrapSearcher struct{}

func (telemetryBootstrapSearcher) Search(context.Context, platformopensearch.SearchRequest) ([]json.RawMessage, error) {
	return []json.RawMessage{json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a"}`)}, nil
}
