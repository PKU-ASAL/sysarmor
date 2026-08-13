package ports

import (
	"context"

	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
)

type HealthSource interface {
	Runtime(context.Context) (domainhealth.Runtime, error)
	Sensor(context.Context) (domainhealth.Sensor, error)
	Telemetry(context.Context) (domainhealth.Telemetry, error)
	Detection(context.Context) (domainhealth.Detection, error)
	Storage(context.Context) (domainhealth.Storage, error)
	Lifecycle(context.Context) (domainhealth.Lifecycle, error)
}
