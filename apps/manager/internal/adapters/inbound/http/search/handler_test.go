package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestSearchUsesAuthenticatedTenantAndPreservesResponse(t *testing.T) {
	service := &searchServiceStub{documents: []domaintelemetry.IndexedDocument{{
		Index:    domaintelemetry.IndexEvents,
		Document: []byte(`{"id":"event-a","tenant_id":"tenant-a","event":{"summary":"shell"}}`),
	}}}
	handler := NewHandler(Options{Service: service, Resolve: searchResolver(t)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/search",
		strings.NewReader(`{"indexes":["events-*"],"query":"shell","limit":25}`))
	recorder := httptest.NewRecorder()
	handler.Search(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"total":1`) ||
		!strings.Contains(recorder.Body.String(), `"id":"event-a"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.request.Actor.TenantID != "tenant-a" || len(service.query.Indexes) != 1 {
		t.Fatalf("request=%+v query=%+v", service.request, service.query)
	}
}

type searchServiceStub struct {
	request   managerapp.RequestContext
	query     telemetryapp.SearchQuery
	documents []domaintelemetry.IndexedDocument
}

func (stub *searchServiceStub) Search(_ context.Context, request managerapp.RequestContext, query telemetryapp.SearchQuery) ([]domaintelemetry.IndexedDocument, error) {
	stub.request, stub.query = request, query
	return stub.documents, nil
}

func searchResolver(t *testing.T) RequestContextResolver {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID,
			Roles: tenant.NewRoleSet(tenant.RoleViewer)}}, nil
	}
}
