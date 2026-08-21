package ports

import (
	"context"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type AnalysisEventFilter struct {
	AgentID string
	Labels  map[string]string
	From    time.Time
	To      time.Time
}

type AnalysisSignalFilter struct {
	AgentID string
	Labels  map[string]string
	From    time.Time
	To      time.Time
	Where   domaintelemetry.SignalWhere
}

type AnalysisTelemetryReader interface {
	Events(context.Context, tenant.ID, AnalysisEventFilter) ([]domaintelemetry.Event, error)
	Signals(context.Context, tenant.ID, AnalysisSignalFilter) ([]domaintelemetry.Signal, error)
}
