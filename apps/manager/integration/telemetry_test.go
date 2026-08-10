package platforme2e

import (
	"context"

	telemetryhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/telemetry"
	managerapi "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/api"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func setTestTelemetryApplication(server *managerapi.Server, memory *store.Store) {
	service := telemetryapp.NewQueryService(testTelemetryReader{store: memory})
	server.SetTelemetryRoutes(telemetryhttp.NewHandler(telemetryhttp.Options{
		Service: service, Resolve: managerapi.PolicyRequestContext,
	}))
}

type testTelemetryReader struct{ store *store.Store }

func (reader testTelemetryReader) Events(_ context.Context, tenantID tenant.ID, filter ports.EventFilter) ([]domaintelemetry.Document, error) {
	return telemetryDocuments(reader.store.ListEventsForTenant(tenantID.String(), store.LabelSelector(filter.Labels), filter.Behavior)), nil
}

func (reader testTelemetryReader) Signals(_ context.Context, tenantID tenant.ID, filter ports.SignalFilter) ([]domaintelemetry.Document, error) {
	terminalOnly := filter.Terminal != nil && *filter.Terminal
	return telemetryDocuments(reader.store.ListSignalsForTenant(tenantID.String(), store.LabelSelector(filter.Labels), filter.Layer, terminalOnly)), nil
}

func (reader testTelemetryReader) Incidents(_ context.Context, tenantID tenant.ID, filter ports.IncidentFilter) ([]domaintelemetry.Document, error) {
	return telemetryDocuments(reader.store.ListIncidentsForTenant(tenantID.String(), store.LabelSelector(filter.Labels))), nil
}

func telemetryDocuments[T proto.Message](values []T) []domaintelemetry.Document {
	result := make([]domaintelemetry.Document, 0, len(values))
	for _, value := range values {
		raw, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(value)
		result = append(result, raw)
	}
	return result
}
