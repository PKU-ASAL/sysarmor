package overview

import (
	"context"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type IdentityQuery interface {
	AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error)
	Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error)
}

type StorageStatus struct {
	Backend               string
	StateVersion          int
	MigrationVersion      int
	PostgresSchemaVersion int
}

type TelemetrySummary struct {
	Events24h  uint64
	Signals24h uint64
}

type Result struct {
	Agents    domainidentity.AgentOverview
	Telemetry TelemetrySummary
	Incidents domaintelemetry.IncidentOverview
	Storage   StorageStatus
}

type Service struct {
	identity  IdentityQuery
	telemetry ports.IncidentOverviewReader
	storage   StorageStatus
}

func NewService(identity IdentityQuery, telemetry ports.IncidentOverviewReader, storage StorageStatus) *Service {
	return &Service{identity: identity, telemetry: telemetry, storage: storage}
}

func (service *Service) Query(ctx context.Context, request managerapp.RequestContext) (Result, error) {
	if err := service.authorize(request); err != nil {
		return Result{}, err
	}
	agents, err := service.identity.AgentOverview(ctx, request)
	if err != nil {
		return Result{}, err
	}
	metrics, err := service.identity.Metrics(ctx, request)
	if err != nil {
		return Result{}, err
	}
	incidents, err := service.telemetry.IncidentOverview(ctx, request.Actor.TenantID)
	if err != nil {
		return Result{}, err
	}
	return Result{Agents: agents, Telemetry: TelemetrySummary{Events24h: metrics.EventsIngested,
		Signals24h: metrics.SignalsEmitted}, Incidents: incidents, Storage: service.storage}, nil
}

func (service *Service) authorize(request managerapp.RequestContext) error {
	if request.Actor.TenantID.IsZero() {
		return failure.New(failure.InvalidArgument, "tenant is required")
	}
	if service == nil || service.identity == nil || service.telemetry == nil {
		return failure.New(failure.Internal, "overview queries are required")
	}
	return request.Actor.Require(tenant.RoleViewer)
}
