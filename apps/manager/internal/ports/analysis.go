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

type AnalysisSignalReader interface {
	Signals(context.Context, tenant.ID, AnalysisSignalFilter) ([]domaintelemetry.Signal, error)
}
