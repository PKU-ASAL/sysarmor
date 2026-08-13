package daemon

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/inbound/unix"
	systemadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/system"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	appdiagnostics "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/diagnostics"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
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
		Status:      statusService,
		Telemetry:   telemetryService,
		Policy:      r.policyController(r, rt, batcher),
		Content:     agentcontrol.NewContentController(newContentApplicationAdapter(r)),
		Enrollment:  coordinator,
		Diagnostics: appdiagnostics.NewService(systemadapter.NewProfileCapturer()),
		Validate:    r.validateControlContext,
	})
	return localapi.New(socketPath, handler, r.Out).Start(ctx)
}

func (r *AgentRuntime) localControlTelemetryArgs(source any, rest ...any) (*telemetryadapter.Bus, *telemetryadapter.Batcher, *telemetryadapter.RuntimeSender, time.Time) {
	if bus, ok := source.(*telemetryadapter.Bus); ok {
		var batcher *telemetryadapter.Batcher
		var sender *telemetryadapter.RuntimeSender
		var startedAt time.Time
		if len(rest) > 0 {
			batcher, _ = rest[0].(*telemetryadapter.Batcher)
		}
		if len(rest) > 1 {
			sender, _ = rest[1].(*telemetryadapter.RuntimeSender)
		}
		if len(rest) > 2 {
			startedAt, _ = rest[2].(time.Time)
		}
		if batcher == nil {
			batcher = telemetryadapter.NewBatcher(r.newTelemetryBatchBuilder().NewBatch, r.Config.Telemetry.MaxBatchItems, r.Config.Telemetry.FlushInterval, 64, r.Config.Telemetry.MaxBatchBytes)
		}
		if sender == nil {
			sender = telemetryadapter.NewRuntimeSender(batcher, localBatchSender{}, 0, 0)
		}
		if startedAt.IsZero() {
			startedAt = time.Now().UTC()
		}
		return bus, batcher, sender, startedAt
	}
	bus := telemetryadapter.NewBus(r.Config.Telemetry.MaxBatchItems * 16)
	batcher := telemetryadapter.NewBatcher(r.newTelemetryBatchBuilder().NewBatch, r.Config.Telemetry.MaxBatchItems, r.Config.Telemetry.FlushInterval, 64, r.Config.Telemetry.MaxBatchBytes)
	sender := telemetryadapter.NewRuntimeSender(batcher, localBatchSender{}, 0, 0)
	startedAt := time.Now().UTC()
	return bus, batcher, sender, startedAt
}

type localStatusService struct {
	runner    *AgentRuntime
	runtime   sensorruntime.Runtime
	bus       *telemetryadapter.Bus
	batcher   *telemetryadapter.Batcher
	sender    *telemetryadapter.RuntimeSender
	startedAt time.Time
}

type localTelemetryService struct {
	runner *AgentRuntime
	bus    *telemetryadapter.Bus
}

func (r *AgentRuntime) configureEnrollmentCoordinator(ctx context.Context, rt sensorruntime.Runtime) *enrollmentCoordinator {
	r.enrollmentCoordinatorMu.Lock()
	defer r.enrollmentCoordinatorMu.Unlock()
	if r.enrollmentCoordinator == nil {
		r.enrollmentCoordinator = newEnrollmentCoordinator(ctx, r, rt)
	}
	return r.enrollmentCoordinator
}
