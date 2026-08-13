package daemon

import (
	"context"
	"time"

	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
)

type TransportRuntime struct {
	runner        *AgentRuntime
	sensor        sensorruntime.Runtime
	bus           *telemetry.Bus
	batcher       *telemetryadapter.Batcher
	sender        *telemetry.Sender
	startedAt     time.Time
	scopeType     string
	scopeSelector string
}

func NewTransportRuntime(runner *AgentRuntime, sensor sensorruntime.Runtime, source any, rest ...any) *TransportRuntime {
	bus, batcher, sender, startedAt, scopeType, scopeSelector := transportArgs(runner, source, rest...)
	return &TransportRuntime{
		runner:        runner,
		sensor:        sensor,
		bus:           bus,
		batcher:       batcher,
		sender:        sender,
		startedAt:     startedAt,
		scopeType:     scopeType,
		scopeSelector: scopeSelector,
	}
}

func transportArgs(runner *AgentRuntime, source any, rest ...any) (*telemetry.Bus, *telemetryadapter.Batcher, *telemetry.Sender, time.Time, string, string) {
	var bus *telemetry.Bus
	var batcher *telemetryadapter.Batcher
	var sender *telemetry.Sender
	var startedAt time.Time
	var scopeType, scopeSelector string
	if b, ok := source.(*telemetry.Bus); ok {
		bus = b
		if len(rest) > 0 {
			batcher, _ = rest[0].(*telemetryadapter.Batcher)
		}
		if len(rest) > 1 {
			sender, _ = rest[1].(*telemetry.Sender)
		}
		if len(rest) > 2 {
			startedAt, _ = rest[2].(time.Time)
		}
		if len(rest) > 3 {
			scopeType, _ = rest[3].(string)
		}
		if len(rest) > 4 {
			scopeSelector, _ = rest[4].(string)
		}
	} else if b, ok := source.(*telemetryadapter.Batcher); ok {
		batcher = b
		if len(rest) > 0 {
			sender, _ = rest[0].(*telemetry.Sender)
		}
		if len(rest) > 1 {
			startedAt, _ = rest[1].(time.Time)
		}
		if len(rest) > 2 {
			scopeType, _ = rest[2].(string)
		}
		if len(rest) > 3 {
			scopeSelector, _ = rest[3].(string)
		}
	}
	if runner == nil {
		return telemetry.NewBus(0), telemetryadapter.NewBatcher(nil, 0, 0, 0), &telemetry.Sender{Appender: localBatchSender{}}, time.Now().UTC(), "", ""
	}
	if bus == nil {
		bus = telemetry.NewBus(runner.Config.Telemetry.MaxBatchItems * 16)
	}
	if batcher == nil {
		batcher = telemetryadapter.NewBatcher(runner.newTelemetryBatchBuilder().NewBatch, runner.Config.Telemetry.MaxBatchItems, runner.Config.Telemetry.FlushInterval, 64, runner.Config.Telemetry.MaxBatchBytes)
	}
	if sender == nil {
		sender = &telemetry.Sender{Appender: localBatchSender{}, Batcher: batcher}
	}
	if sender.Batcher == nil {
		sender.Batcher = batcher
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	return bus, batcher, sender, startedAt, scopeType, scopeSelector
}

func (r *TransportRuntime) RunDataFlow(ctx context.Context) {
	if r == nil || r.runner == nil {
		return
	}
	go r.batcher.Run(ctx)
	r.sender.Run(ctx)
}

func (r *TransportRuntime) RunControlFlow(ctx context.Context) {
	if r == nil || r.runner == nil || r.runner.Config.Manager.Transport != "grpc" {
		return
	}
	r.runControlFlow(ctx)
}
