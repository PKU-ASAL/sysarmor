package ports

import (
	"context"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type EventFilter struct {
	Labels   map[string]string
	Behavior string
	Limit    int
	Offset   int
}

type SignalFilter struct {
	Labels   map[string]string
	Layer    string
	Terminal *bool
	Limit    int
	Offset   int
}

type IncidentFilter struct {
	Labels map[string]string
	ID     string
	Limit  int
	Offset int
}

type TelemetryReader interface {
	Events(context.Context, tenant.ID, EventFilter) ([]domaintelemetry.Document, error)
	Signals(context.Context, tenant.ID, SignalFilter) ([]domaintelemetry.Document, error)
	Incidents(context.Context, tenant.ID, IncidentFilter) ([]domaintelemetry.Document, error)
}

type TelemetrySearchFilter struct {
	Index     domaintelemetry.Index
	Query     string
	Exact     map[string]string
	Limit     int
	Offset    int
	TimeField string
	TimeFrom  string
	TimeTo    string
	SortField string
	SortDesc  bool
}

type TelemetrySearchReader interface {
	Search(context.Context, tenant.ID, TelemetrySearchFilter) ([]domaintelemetry.IndexedDocument, error)
}

type IncidentOverviewReader interface {
	IncidentOverview(context.Context, tenant.ID) (domaintelemetry.IncidentOverview, error)
}
