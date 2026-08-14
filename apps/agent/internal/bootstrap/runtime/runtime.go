package runtime

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Options struct {
	Out io.Writer
}

type Coordinator struct {
	Config config.Config
	Sensor contract.Sensor
	Out    io.Writer
	policyRuntime
	managementRuntime
	telemetryRuntime
	sensorRuntime
}

type policyRuntime struct {
	mu                 sync.RWMutex
	detectionUpdateMu  sync.Mutex
	policyAuthorityMu  sync.RWMutex
	endpointPolicy     policymodel.EndpointPolicy
	effectiveTelemetry config.EffectiveTelemetry
	policy             policymodel.Policy
	detection          *detectionruntime.State
	collection         contract.CollectionIntent
	content            *agentcontent.Store
	featureFlags       agenthealth.RuntimeFeatureFlags
	detectionStatus    agenthealth.DetectionHealth
	policyController   PolicyControllerFactory
}

type managementRuntime struct {
	mu                      sync.RWMutex
	localStore              *sqlite.Store
	network                 *networkSupervisor
	enrollmentCoordinatorMu sync.Mutex
	enrollmentCoordinator   *enrollmentCoordinator
	completionReporter      *unenrollmentCompletionReporter
	identity                runtimeIdentity
	standaloneIdentity      runtimeIdentity
	managedControl          *TransportRuntime
	revokeEnrollment        func(context.Context, sqlite.Enrollment, string) (string, time.Time, error)
	reportUnenrollment      func(context.Context) (bool, error)
}

type telemetryRuntime struct {
	mu                    sync.RWMutex
	normalizer            *eventadapter.EventNormalizer
	telemetryBatcher      *telemetryadapter.Batcher
	eventSeq              uint64
	initialSignalSequence uint64
	telemetrySeq          uint64
}

type sensorRuntime struct {
	mu               sync.RWMutex
	capability       contract.Capability
	sensorSupervisor *sensorruntime.SubscriptionSupervisor
}

type Dependencies struct {
	Config       config.Config
	Sensor       contract.Sensor
	Content      *agentcontent.Store
	LocalStore   *sqlite.Store
	FeatureFlags agenthealth.RuntimeFeatureFlags
	EventSeq     uint64
	SignalSeq    uint64
	Policy       PolicyControllerFactory
}

type PolicyControllerFactory func(*Coordinator, sensorruntime.Runtime, *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController

func (r *Coordinator) withDetectionUpdateTransaction(fn func()) {
	r.detectionUpdateMu.Lock()
	defer r.detectionUpdateMu.Unlock()
	fn()
}

func NewCoordinator(dependencies Dependencies) (*Coordinator, error) {
	if dependencies.Sensor == nil {
		return nil, fmt.Errorf("runtime sensor dependency is required")
	}
	if dependencies.Content == nil {
		return nil, fmt.Errorf("runtime content dependency is required")
	}
	if dependencies.Policy == nil {
		return nil, fmt.Errorf("runtime policy controller factory is required")
	}
	runtime := &Coordinator{Config: dependencies.Config, Sensor: dependencies.Sensor}
	runtime.policyRuntime.content = dependencies.Content
	runtime.policyRuntime.featureFlags = dependencies.FeatureFlags
	runtime.managementRuntime.localStore = dependencies.LocalStore
	runtime.telemetryRuntime.eventSeq = dependencies.EventSeq
	runtime.telemetryRuntime.initialSignalSequence = dependencies.SignalSeq
	runtime.policyController = dependencies.Policy
	runtime.setRuntimeIdentity(runtimeIdentity{
		AgentID:  dependencies.Config.Agent.ID,
		HostID:   dependencies.Config.Agent.HostID,
		TenantID: dependencies.Config.Agent.TenantID,
	})
	return runtime, nil
}

func (r *Coordinator) Run(ctx context.Context, opts Options) error {
	if opts.Out != nil {
		r.Out = opts.Out
	}
	if r.localStore != nil {
		defer r.startUnenrollmentCompletionReporter(ctx)()
	}
	startedAt := time.Now()
	reporter := r.healthReporter()
	failStartup := func(stage string, err error) error {
		r.reportStartupFailure(reporter, startedAt, stage, err)
		return err
	}
	startup, err := r.prepareRuntime(ctx, failStartup)
	if err != nil {
		return err
	}
	active, err := r.startRuntime(ctx, startup, reporter, startedAt, failStartup)
	if err != nil {
		return err
	}
	defer active.Close()
	r.logRuntimeStarted(startup)
	return r.serveRuntime(ctx, active, reporter, startedAt)
}
