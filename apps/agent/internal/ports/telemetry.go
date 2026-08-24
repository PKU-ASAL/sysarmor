package ports

import (
	"context"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
)

type TelemetryContext struct {
	EnrollmentEpoch string
	TenantID        string
	AgentID         string
	HostID          string
	PolicyID        string
	PolicyVersion   uint64
	PolicyMode      string
	Labels          map[string]string
}

type TelemetryContextProvider interface {
	TelemetryContext() TelemetryContext
}

type TelemetrySpool interface {
	Checkpoint(context.Context) (domaintelemetry.Position, error)
	Read(context.Context, uint64, int) ([]domaintelemetry.StoredBatch, error)
	SaveCheckpoint(context.Context, domaintelemetry.Position) error
}

type TelemetrySender interface {
	Send(context.Context, domaintelemetry.Batch) (domaintelemetry.DeliveryOutcome, error)
}
