package daemon

import (
	"context"
	"time"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localapi"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
)

func (r *AgentRuntime) startLocalControlServer(ctx context.Context, rt sensorruntime.Runtime, source any, rest ...any) (func(), error) {
	coordinator := r.configureEnrollmentCoordinator(ctx, rt)
	bus, batcher, sender, startedAt := r.localControlTelemetryArgs(source, rest...)
	socketPath := r.Config.Control.SocketPath
	statusService := &localStatusService{
		runner:    r,
		runtime:   rt,
		bus:       bus,
		batcher:   batcher,
		sender:    sender,
		startedAt: startedAt,
	}
	telemetryService := &localTelemetryService{runner: r, bus: bus}
	handler := localapi.NewHandler(localapi.Dependencies{
		Status:     statusService,
		Telemetry:  telemetryService,
		Policy:     r.policyController(r, rt, batcher),
		Content:    agentcontrol.NewContentController(newContentApplicationAdapter(r)),
		Enrollment: coordinator,
		Validate:   r.validateControlContext,
	})
	return localapi.New(socketPath, handler, r.Out).Start(ctx)
}

func (r *AgentRuntime) localControlTelemetryArgs(source any, rest ...any) (*telemetry.Bus, *telemetry.Batcher, *telemetry.Sender, time.Time) {
	if bus, ok := source.(*telemetry.Bus); ok {
		var batcher *telemetry.Batcher
		var sender *telemetry.Sender
		var startedAt time.Time
		if len(rest) > 0 {
			batcher, _ = rest[0].(*telemetry.Batcher)
		}
		if len(rest) > 1 {
			sender, _ = rest[1].(*telemetry.Sender)
		}
		if len(rest) > 2 {
			startedAt, _ = rest[2].(time.Time)
		}
		if batcher == nil {
			batcher = telemetry.NewBatcher(r.newTelemetryBatchBuilder().NewBatch, r.Config.Telemetry.MaxBatchItems, r.Config.Telemetry.FlushInterval, 64, r.Config.Telemetry.MaxBatchBytes)
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
		return bus, batcher, sender, startedAt
	}
	bus := telemetry.NewBus(r.Config.Telemetry.MaxBatchItems * 16)
	batcher := telemetry.NewBatcher(r.newTelemetryBatchBuilder().NewBatch, r.Config.Telemetry.MaxBatchItems, r.Config.Telemetry.FlushInterval, 64, r.Config.Telemetry.MaxBatchBytes)
	sender := &telemetry.Sender{Appender: localBatchSender{}, Batcher: batcher}
	startedAt := time.Now().UTC()
	return bus, batcher, sender, startedAt
}

type localStatusService struct {
	runner    *AgentRuntime
	runtime   sensorruntime.Runtime
	bus       *telemetry.Bus
	batcher   *telemetry.Batcher
	sender    *telemetry.Sender
	startedAt time.Time
}

type localTelemetryService struct {
	runner *AgentRuntime
	bus    *telemetry.Bus
}

func (r *AgentRuntime) configureEnrollmentCoordinator(ctx context.Context, rt sensorruntime.Runtime) *enrollmentCoordinator {
	r.enrollmentCoordinatorMu.Lock()
	defer r.enrollmentCoordinatorMu.Unlock()
	if r.enrollmentCoordinator == nil {
		r.enrollmentCoordinator = newEnrollmentCoordinator(ctx, r, rt)
	}
	return r.enrollmentCoordinator
}
