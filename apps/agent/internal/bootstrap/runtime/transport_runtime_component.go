package runtime

import (
	"context"
	"io"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type transportRuntimeDependencies struct {
	config      config.Config
	out         io.Writer
	sensorPort  contract.Sensor
	policy      *policyRuntime
	management  *managementRuntime
	telemetry   *telemetryRuntime
	sensorState *sensorRuntime
}

type TransportRuntime struct {
	dependencies  transportRuntimeDependencies
	sensor        sensorruntime.Runtime
	bus           *telemetryadapter.Bus
	batcher       *telemetryadapter.Batcher
	sender        *telemetryadapter.RuntimeSender
	startedAt     time.Time
	scopeType     string
	scopeSelector string
}

func NewTransportRuntime(dependencies transportRuntimeDependencies, sensor sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time, scopeType, scopeSelector string) *TransportRuntime {
	return &TransportRuntime{
		dependencies:  dependencies,
		sensor:        sensor,
		bus:           bus,
		batcher:       batcher,
		sender:        sender,
		startedAt:     startedAt,
		scopeType:     scopeType,
		scopeSelector: scopeSelector,
	}
}

func (r *TransportRuntime) RunDataFlow(ctx context.Context) {
	if r == nil || r.dependencies.policy == nil {
		return
	}
	go r.batcher.Run(ctx)
	r.sender.Run(ctx)
}

func (r *TransportRuntime) RunControlFlow(ctx context.Context) {
	if r == nil || r.dependencies.policy == nil || r.dependencies.config.Manager.Transport != "grpc" {
		return
	}
	r.runControlFlow(ctx)
}
