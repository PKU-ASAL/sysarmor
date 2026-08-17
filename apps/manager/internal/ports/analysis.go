package ports

import (
	"context"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type AnalysisSignalFilter struct {
	Labels map[string]string
	Layer  string
}

type AnalysisTelemetryReader interface {
	Events(context.Context, tenant.ID, map[string]string) ([]domaintelemetry.Event, error)
	Signals(context.Context, tenant.ID, AnalysisSignalFilter) ([]domaintelemetry.Signal, error)
}
