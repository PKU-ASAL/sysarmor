package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestTelemetryReaderScopesAndFiltersEventsByTenant(t *testing.T) {
	searcher := &telemetryQuerySearcherStub{documents: []json.RawMessage{
		json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a","behavior":"process.exec","labels":{"env":"prod"}}`),
		json.RawMessage(`{"id":"event-b","tenant_id":"tenant-b","behavior":"process.exec","labels":{"env":"prod"}}`),
	}}
	reader := NewTelemetryReader(searcher)
	result, err := reader.Events(context.Background(), tenant.ID("tenant-a"), ports.EventFilter{
		Labels: map[string]string{"env": "prod"}, Behavior: "process.exec", Limit: 25, Offset: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || searcher.request.Exact["tenant_id"] != "tenant-a" || searcher.request.Size != 25 || searcher.request.Offset != 5 {
		t.Fatalf("result=%q request=%+v", result, searcher.request)
	}
}

func TestTelemetryReaderRequiresTenant(t *testing.T) {
	searcher := &telemetryQuerySearcherStub{}
	reader := NewTelemetryReader(searcher)
	_, err := reader.Events(context.Background(), tenant.ID(""), ports.EventFilter{})
	if failure.KindOf(err) != failure.InvalidArgument || searcher.calls != 0 {
		t.Fatalf("kind=%v error=%v calls=%d", failure.KindOf(err), err, searcher.calls)
	}
}

func TestTelemetryReaderClassifiesSearchFailureAsRetryableDependency(t *testing.T) {
	reader := NewTelemetryReader(&telemetryQuerySearcherStub{err: errors.New("unavailable")})
	_, err := reader.Events(context.Background(), tenant.ID("tenant-a"), ports.EventFilter{})
	if failure.KindOf(err) != failure.RetryableDependency {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestTelemetryReaderFiltersSignalsAndIncidents(t *testing.T) {
	searcher := &telemetryQuerySearcherStub{documents: []json.RawMessage{
		json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","where":"SIGNAL_WHERE_ENDPOINT","terminal":true}`),
		json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-a","where":"SIGNAL_WHERE_CLOUD","terminal":true}`),
	}}
	reader := NewTelemetryReader(searcher)
	terminal := true
	signals, err := reader.Signals(context.Background(), tenant.ID("tenant-a"), ports.SignalFilter{
		Layer: "endpoint", Terminal: &terminal,
	})
	if err != nil || len(signals) != 1 || searcher.request.Bool["terminal"] != true {
		t.Fatalf("signals=%q request=%+v error=%v", signals, searcher.request, err)
	}
	searcher.documents = []json.RawMessage{
		json.RawMessage(`{"id":"incident-a","tenant_id":"tenant-a"}`),
		json.RawMessage(`{"id":"incident-b","tenant_id":"tenant-a"}`),
	}
	incidents, err := reader.Incidents(context.Background(), tenant.ID("tenant-a"), ports.IncidentFilter{ID: "incident-a"})
	if err != nil || len(incidents) != 1 || searcher.request.Exact["id"] != "incident-a" {
		t.Fatalf("incidents=%q request=%+v error=%v", incidents, searcher.request, err)
	}
}

func TestTelemetrySearchReaderMapsFieldsAndFiltersTenant(t *testing.T) {
	searcher := &telemetryQuerySearcherStub{documents: []json.RawMessage{
		json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a"}`),
		json.RawMessage(`{"id":"event-b","tenant_id":"tenant-b"}`),
	}}
	reader := NewTelemetryReader(searcher)
	result, err := reader.Search(context.Background(), tenant.ID("tenant-a"), ports.TelemetrySearchFilter{
		Index: domaintelemetry.IndexEvents, Exact: map[string]string{"event.action": "exec"}, Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Index != domaintelemetry.IndexEvents ||
		searcher.request.Exact["tenant_id"] != "tenant-a" || searcher.request.Exact["event.action.keyword"] != "exec" {
		t.Fatalf("result=%+v request=%+v", result, searcher.request)
	}
}

type telemetryQuerySearcherStub struct {
	request   SearchRequest
	documents []json.RawMessage
	err       error
	calls     int
}

func (stub *telemetryQuerySearcherStub) Search(_ context.Context, request SearchRequest) ([]json.RawMessage, error) {
	stub.request = request
	stub.calls++
	return stub.documents, stub.err
}
