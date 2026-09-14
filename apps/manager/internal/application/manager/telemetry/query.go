package telemetry

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type EventQuery struct {
	Labels   map[string]string
	Behavior string
	Limit    int
	Offset   int
}

type SignalQuery struct {
	Labels map[string]string
	Layer  string
	Stage  *domaintelemetry.SignalStage
	Limit  int
	Offset int
}

type IncidentQuery struct {
	Labels map[string]string
	ID     string
	Limit  int
	Offset int
}

type QueryService struct{ reader ports.TelemetryReader }

func NewQueryService(reader ports.TelemetryReader) *QueryService {
	return &QueryService{reader: reader}
}

func (service *QueryService) Events(ctx context.Context, request managerapp.RequestContext, query EventQuery) ([]domaintelemetry.Document, error) {
	if err := service.authorize(request); err != nil {
		return nil, err
	}
	return service.reader.Events(ctx, request.Actor.TenantID, ports.EventFilter{Labels: cloneLabels(query.Labels),
		Behavior: strings.TrimSpace(query.Behavior), Limit: query.Limit, Offset: query.Offset})
}

func (service *QueryService) Signals(ctx context.Context, request managerapp.RequestContext, query SignalQuery) ([]domaintelemetry.Document, error) {
	if err := service.authorize(request); err != nil {
		return nil, err
	}
	if query.Stage != nil && *query.Stage != domaintelemetry.SignalStageCandidate && *query.Stage != domaintelemetry.SignalStageConclusion {
		return nil, failure.New(failure.InvalidArgument, "signal stage must be candidate or conclusion")
	}
	return service.reader.Signals(ctx, request.Actor.TenantID, ports.SignalFilter{Labels: cloneLabels(query.Labels),
		Layer: strings.TrimSpace(query.Layer), Stage: query.Stage, Limit: query.Limit, Offset: query.Offset})
}

func (service *QueryService) Incidents(ctx context.Context, request managerapp.RequestContext, query IncidentQuery) ([]domaintelemetry.Document, error) {
	if err := service.authorize(request); err != nil {
		return nil, err
	}
	return service.reader.Incidents(ctx, request.Actor.TenantID, ports.IncidentFilter{
		Labels: cloneLabels(query.Labels), ID: strings.TrimSpace(query.ID), Limit: query.Limit, Offset: query.Offset})
}

func (service *QueryService) authorize(request managerapp.RequestContext) error {
	if request.Actor.TenantID.IsZero() {
		return failure.New(failure.InvalidArgument, "tenant is required")
	}
	if service == nil || service.reader == nil {
		return failure.New(failure.Internal, "telemetry reader is required")
	}
	return request.Actor.Require(tenant.RoleViewer)
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
