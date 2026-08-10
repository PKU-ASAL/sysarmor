package managerapi

import (
	"context"

	searchhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/search"
	telemetryhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/telemetry"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func setTestSearchApplication(server *Server, searcher platformopensearch.Searcher) {
	reader := platformopensearch.NewTelemetryReader(searcher)
	service := telemetryapp.NewSearchService(reader)
	server.SetSearchRoutes(searchhttp.NewHandler(searchhttp.Options{
		Service: service, Resolve: PolicyRequestContext,
	}))
}

func setTestTelemetryApplication(server *Server, memory *store.Store) {
	var reader ports.TelemetryReader = testStoreTelemetryReader{store: memory}
	if server.searcher != nil {
		reader = platformopensearch.NewTelemetryReader(server.searcher)
	}
	service := telemetryapp.NewQueryService(reader)
	server.SetTelemetryRoutes(telemetryhttp.NewHandler(telemetryhttp.Options{
		Service: service, Resolve: PolicyRequestContext,
	}))
}

type testStoreTelemetryReader struct{ store *store.Store }

func (reader testStoreTelemetryReader) Events(_ context.Context, tenantID tenant.ID, filter ports.EventFilter) ([]domaintelemetry.Document, error) {
	values := reader.store.ListEventsForTenant(tenantID.String(), store.LabelSelector(filter.Labels), filter.Behavior)
	return testDocuments(pageTestValues(values, filter.Limit, filter.Offset)), nil
}

func (reader testStoreTelemetryReader) Signals(_ context.Context, tenantID tenant.ID, filter ports.SignalFilter) ([]domaintelemetry.Document, error) {
	terminalOnly := filter.Terminal != nil && *filter.Terminal
	values := reader.store.ListSignalsForTenant(tenantID.String(), store.LabelSelector(filter.Labels), filter.Layer, terminalOnly)
	return testDocuments(pageTestValues(values, filter.Limit, filter.Offset)), nil
}

func (reader testStoreTelemetryReader) Incidents(_ context.Context, tenantID tenant.ID, filter ports.IncidentFilter) ([]domaintelemetry.Document, error) {
	values := reader.store.ListIncidentsForTenant(tenantID.String(), store.LabelSelector(filter.Labels))
	if filter.ID != "" {
		filtered := values[:0]
		for _, value := range values {
			if value.GetId() == filter.ID {
				filtered = append(filtered, value)
			}
		}
		values = filtered
	}
	return testDocuments(pageTestValues(values, filter.Limit, filter.Offset)), nil
}

func testDocuments[T proto.Message](values []T) []domaintelemetry.Document {
	result := make([]domaintelemetry.Document, 0, len(values))
	for _, value := range values {
		raw, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(value)
		result = append(result, raw)
	}
	return result
}

func pageTestValues[T any](values []T, limit, offset int) []T {
	if offset >= len(values) {
		return []T{}
	}
	values = values[offset:]
	if limit > 0 && limit < len(values) {
		values = values[:limit]
	}
	return values
}
