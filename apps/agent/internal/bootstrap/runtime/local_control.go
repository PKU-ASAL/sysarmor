package runtime

import (
	"context"
	"io"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/inbound/unix"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	systemadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/system"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	appdiagnostics "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/diagnostics"
)

type localControlRuntime struct {
	config     config.Config
	out        io.Writer
	policy     *policyRuntime
	management *managementRuntime
	sensor     *sensorRuntime
}

func (r localControlRuntime) start(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) (func(), error) {
	coordinator := r.management.configureEnrollmentCoordinator(ctx, rt)
	socketPath := r.config.Control.SocketPath
	statusService := &localStatusService{
		health:    newRuntimeHealth(r.config, r.out, r.policy, r.management, r.sensor),
		runtime:   rt,
		bus:       bus,
		batcher:   batcher,
		sender:    sender,
		startedAt: startedAt,
	}
	telemetryService := &localTelemetryService{management: r.management, bus: bus}
	handler := localapi.NewHandler(localapi.Dependencies{
		Status:      statusService,
		Telemetry:   telemetryService,
		Policy:      r.policy.policyController(rt, batcher),
		Content:     agentcontrol.NewContentController(newContentApplicationAdapter(r.policy)),
		Enrollment:  coordinator,
		Diagnostics: appdiagnostics.NewService(systemadapter.NewProfileCapturer()),
		Validate:    r.management.validateControlContext,
	})
	return localapi.New(socketPath, handler, r.out).Start(ctx)
}

type localStatusService struct {
	health    runtimeHealth
	runtime   sensorruntime.Runtime
	bus       *telemetryadapter.Bus
	batcher   *telemetryadapter.Batcher
	sender    *telemetryadapter.RuntimeSender
	startedAt time.Time
}

type localTelemetryService struct {
	management *managementRuntime
	bus        *telemetryadapter.Bus
}

func (r *managementRuntime) configureEnrollmentCoordinator(ctx context.Context, rt sensorruntime.Runtime) *enrollmentCoordinator {
	r.enrollmentCoordinatorMu.Lock()
	defer r.enrollmentCoordinatorMu.Unlock()
	if r.enrollmentCoordinator == nil {
		r.enrollmentCoordinator = newEnrollmentCoordinator(ctx, r, rt)
	}
	return r.enrollmentCoordinator
}
