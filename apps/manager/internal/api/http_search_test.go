package managerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestSearchFieldsReturnsAllowlistedTelemetryFields(t *testing.T) {
	handler := NewServer(&store.Store{}).Handler()

	rec := get(t, handler, "/api/v1/search/fields?index=events-*,signals-*")

	for _, want := range []string{
		`"indexes":["sysarmor-events-read","sysarmor-signals-read"]`,
		`"name":"@timestamp"`,
		`"name":"host.name"`,
		`"name":"event.severity"`,
		`"searchable":true`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("fields response missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestSearchTelemetryReturnsDiscoverRows(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		"sysarmor-events-read": {
			json.RawMessage(`{"id":"evt-a","tenant_id":"default","@timestamp":"2026-07-08T21:04:18Z","host":{"name":"prod-api-01"},"event":{"kind":"event","summary":"process execution","tactic":"Execution","severity":"medium"}}`),
			json.RawMessage(`{"id":"evt-b","tenant_id":"default","@timestamp":"2026-07-08T21:05:18Z","host":{"name":"prod-db-01"},"event":{"kind":"event","summary":"file write","severity":"info"}}`),
		},
		"sysarmor-signals-read": {
			json.RawMessage(`{"id":"sig-a","tenant_id":"default","@timestamp":"2026-07-08T21:06:18Z","host":{"name":"prod-api-01"},"event":{"kind":"signal","summary":"credential access","tactic":"CredentialAccess","severity":"critical"}}`),
		},
	}}
	handler := adminTestHandler(NewServerWithSearch(&store.Store{}, searcher))
	body := `{"indexes":["sysarmor-events-read","sysarmor-signals-read"],"query":"host.name:prod-api-01","time":{"field":"@timestamp","from":"2026-07-08T21:00:00Z","to":"2026-07-08T21:10:00Z"},"limit":50,"offset":0}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("search status = %d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`"total":2`,
		`"index":"sysarmor-events-read"`,
		`"id":"evt-a"`,
		`"index":"sysarmor-signals-read"`,
		`"id":"sig-a"`,
		`"summary":"credential access"`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("search response missing %s: %s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), `"id":"evt-b"`) {
		t.Fatalf("search response included filtered row: %s", rec.Body.String())
	}
	if len(searcher.requests) != 2 {
		t.Fatalf("search requests = %d, want 2", len(searcher.requests))
	}
	if searcher.requests[0].Index != "sysarmor-events-read" || searcher.requests[1].Index != "sysarmor-signals-read" {
		t.Fatalf("search indexes = %#v", searcher.requests)
	}
	for _, request := range searcher.requests {
		if request.Exact["host.name.keyword"] != "prod-api-01" || request.Exact["host.name"] != "" {
			t.Fatalf("search exact fields = %#v", request.Exact)
		}
	}
}

func TestSearchTelemetryRejectsUnsupportedField(t *testing.T) {
	handler := adminTestHandler(NewServerWithSearch(&store.Store{}, &recordingSearcher{}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"indexes":["sysarmor-events-read"],"query":"process.args:curl"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("search status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unsupported search field") {
		t.Fatalf("search error mismatch: %s", rec.Body.String())
	}
}

func TestIncidentsSearchUsesTopLevelTenantField(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.IncidentsReadAlias: {
			json.RawMessage(`{"id":"inc-a","tenant_id":"default","labels":{"scenario":"apt-fileless-c2-managed"}}`),
		},
	}}
	handler := NewServerWithSearch(&store.Store{}, searcher).Handler()
	rec := get(t, handler, "/api/v1/incidents?tenant_id=default&label=scenario=apt-fileless-c2-managed")

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"inc-a"`) {
		t.Fatalf("incidents status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(searcher.requests) != 1 {
		t.Fatalf("search requests = %d, want 1", len(searcher.requests))
	}
	request := searcher.requests[0]
	if request.Exact["tenant_id"] != "default" || request.Labels["tenant_id"] != "" {
		t.Fatalf("incident tenant filters = exact:%v labels:%v", request.Exact, request.Labels)
	}
}

func TestSearchHistogramReturnsTimeBuckets(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		"sysarmor-signals-read": {
			json.RawMessage(`{"id":"sig-a","tenant_id":"default","@timestamp":"2026-07-08T21:01:00Z","host":{"name":"prod-api-01"},"event":{"kind":"signal","severity":"critical","summary":"credential access"}}`),
			json.RawMessage(`{"id":"sig-b","tenant_id":"default","@timestamp":"2026-07-08T21:06:00Z","host":{"name":"prod-api-01"},"event":{"kind":"signal","severity":"high","summary":"lateral movement"}}`),
		},
	}}
	handler := adminTestHandler(NewServerWithSearch(&store.Store{}, searcher))
	body := `{"indexes":["sysarmor-signals-read"],"time":{"field":"@timestamp","from":"2026-07-08T21:00:00Z","to":"2026-07-08T21:10:00Z"},"bucket_count":2}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search/histogram", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("histogram status = %d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`"total":1`,
		`"signals":1`,
		`"events":0`,
		`"start":"2026-07-08T21:00:00Z"`,
		`"start":"2026-07-08T21:05:00Z"`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("histogram response missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestTelemetrySearchScopesEveryIndexToPrincipalTenant(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.EventsReadAlias: {
			json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a","@timestamp":"2026-07-08T21:01:00Z"}`),
			json.RawMessage(`{"id":"event-b","tenant_id":"tenant-b","@timestamp":"2026-07-08T21:02:00Z"}`),
		},
		platformopensearch.SignalsReadAlias: {
			json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","@timestamp":"2026-07-08T21:03:00Z"}`),
			json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-b","@timestamp":"2026-07-08T21:04:00Z"}`),
		},
	}}
	handler := tenantTestHandler(NewServerWithSearch(&store.Store{}, searcher), "tenant-a")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"indexes":["events-*","signals-*"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "event-b") || strings.Contains(rec.Body.String(), "signal-b") {
		t.Fatalf("search leaked tenant-b documents: %s", rec.Body.String())
	}
	for _, request := range searcher.requests {
		if request.Exact["tenant_id"] != "tenant-a" {
			t.Fatalf("search tenant filter = %#v", request.Exact)
		}
	}
}

func TestTelemetryHistogramScopesCountsToPrincipalTenant(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.SignalsReadAlias: {
			json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","@timestamp":"2026-07-08T21:01:00Z"}`),
			json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-b","@timestamp":"2026-07-08T21:02:00Z"}`),
		},
	}}
	handler := tenantTestHandler(NewServerWithSearch(&store.Store{}, searcher), "tenant-a")
	body := `{"indexes":["signals-*"],"time":{"from":"2026-07-08T21:00:00Z","to":"2026-07-08T21:10:00Z"},"bucket_count":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search/histogram", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("histogram includes another tenant: %s", rec.Body.String())
	}
	if len(searcher.requests) != 1 || searcher.requests[0].Exact["tenant_id"] != "tenant-a" {
		t.Fatalf("histogram requests = %#v", searcher.requests)
	}
}

func tenantTestHandler(server *Server, tenantID string) http.Handler {
	return (&authenticatedTestServer{
		Server: server,
		principal: managerauth.Principal{
			Subject: "viewer", TenantID: tenantID, Roles: []string{"viewer"},
		},
	}).Handler()
}

type recordingSearcher struct {
	docs     map[string][]json.RawMessage
	requests []platformopensearch.SearchRequest
}

func (s *recordingSearcher) Search(_ context.Context, search platformopensearch.SearchRequest) ([]json.RawMessage, error) {
	s.requests = append(s.requests, search)
	if s.docs == nil {
		return nil, nil
	}
	return append([]json.RawMessage(nil), s.docs[search.Index]...), nil
}
