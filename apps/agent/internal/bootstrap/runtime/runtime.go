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
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Options struct {
	Out io.Writer
}

type Coordinator struct {
	Config           config.Config
	Sensor           contract.Sensor
	Out              io.Writer
	policyState      policyRuntime
	managementState  managementRuntime
	telemetryState   telemetryRuntime
	sensorState      sensorRuntime
	processProfiles  *domainprocess.Profiles
	learningDetector ports.EventDetector
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
	config             config.Config
	management         *managementRuntime
	telemetry          *telemetryRuntime
	sensor             *sensorRuntime
	out                io.Writer
	controller         PolicyControllerFactory
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
	normalizer              *eventadapter.EventNormalizer
	managedControl          *TransportRuntime
	revokeEnrollment        func(context.Context, sqlite.Enrollment, string) (string, time.Time, error)
	reportUnenrollment      func(context.Context) (bool, error)
	processProfiles         *domainprocess.Profiles
	config                  config.Config
	policy                  *policyRuntime
	telemetry               *telemetryRuntime
}

type telemetryRuntime struct {
	telemetryBatcher      *telemetryadapter.Batcher
	eventSeq              uint64
	initialSignalSequence uint64
	telemetrySeq          uint64
	config                config.Config
	management            *managementRuntime
	policy                *policyRuntime
}

type sensorRuntime struct {
	mu               sync.RWMutex
	capability       contract.Capability
	sensorSupervisor *sensorruntime.SubscriptionSupervisor
	config           config.Config
}

type Dependencies struct {
	Config           config.Config
	Sensor           contract.Sensor
	Content          *agentcontent.Store
	LocalStore       *sqlite.Store
	FeatureFlags     agenthealth.RuntimeFeatureFlags
	EventSeq         uint64
	SignalSeq        uint64
	Policy           PolicyControllerFactory
	LearningDetector ports.EventDetector
	LearningError    error
}

type PolicyApplications struct {
	StandaloneEndpoint agentcontrol.EndpointApplication
	ManagedEndpoint    agentcontrol.EndpointApplication
	Collection         agentcontrol.CollectionApplication
	Detection          agentcontrol.DetectionApplication
	Telemetry          agentcontrol.TelemetryApplication
}

type PolicyControllerFactory func(agentcontrol.PolicyControllerRuntime, PolicyApplications) *agentcontrol.ApplicationPolicyController

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
	profiles, err := domainprocess.NewProfiles(processProfileLimits(dependencies.Config))
	if err != nil {
		return nil, fmt.Errorf("initialize process profiles: %w", err)
	}
	runtime := &Coordinator{Config: dependencies.Config, Sensor: dependencies.Sensor, processProfiles: profiles}
	runtime.policyState.content = dependencies.Content
	runtime.policyState.featureFlags = dependencies.FeatureFlags
	runtime.policyState.controller = dependencies.Policy
	runtime.managementState.localStore = dependencies.LocalStore
	runtime.telemetryState.eventSeq = dependencies.EventSeq
	runtime.telemetryState.initialSignalSequence = dependencies.SignalSeq
	runtime.learningDetector = dependencies.LearningDetector
	runtime.policyState.detectionStatus.Learning = learningHealth(dependencies.LearningDetector, dependencies.LearningError)
	runtime.wireComponents()
	runtime.managementState.setRuntimeIdentity(runtimeIdentity{
		AgentID:  dependencies.Config.Agent.ID,
		HostID:   dependencies.Config.Agent.HostID,
		TenantID: dependencies.Config.Agent.TenantID,
	})
	return runtime, nil
}

func processProfileLimits(cfg config.Config) domainprocess.Limits {
	maxProfiles := cfg.Sensor.ProcessCacheSize
	if maxProfiles <= 0 {
		maxProfiles = 4096
	}
	return domainprocess.Limits{
		MaxProfiles: maxProfiles, MaxFiles: 32, MaxNetworks: 16, MaxEventRefs: 16,
		ExitGrace: 30 * time.Second, RetainedTTL: 5 * time.Minute, SweepInterval: 30 * time.Second,
	}
}

func learningHealth(detector ports.EventDetector, loadErr error) agenthealth.LearningHealth {
	if loadErr != nil {
		return agenthealth.LearningHealth{Status: "degraded", LastError: loadErr.Error()}
	}
	if detector != nil {
		return agenthealth.LearningHealth{Status: "loaded"}
	}
	return agenthealth.LearningHealth{Status: "disabled"}
}

func (r *Coordinator) wireComponents() {
	r.policyState.config = r.Config
	r.policyState.management = &r.managementState
	r.policyState.telemetry = &r.telemetryState
	r.policyState.sensor = &r.sensorState
	r.policyState.out = r.Out
	r.managementState.config = r.Config
	r.managementState.policy = &r.policyState
	r.managementState.telemetry = &r.telemetryState
	r.managementState.processProfiles = r.processProfiles
	r.telemetryState.config = r.Config
	r.telemetryState.management = &r.managementState
	r.telemetryState.policy = &r.policyState
	r.sensorState.config = r.Config
}

func (r *Coordinator) Run(ctx context.Context, opts Options) error {
	if opts.Out != nil {
		r.Out = opts.Out
	}
	r.wireComponents()
	if r.managementState.localStore != nil {
		defer r.managementState.startUnenrollmentCompletionReporter(ctx)()
	}
	startedAt := time.Now()
	health := r.healthRuntime()
	failStartup := func(stage string, err error) error {
		health.reportStartupFailure(stage, err)
		return err
	}
	startup, err := r.prepareRuntime(ctx, failStartup)
	if err != nil {
		return err
	}
	active, err := r.startRuntime(ctx, &startup, startedAt, failStartup)
	if err != nil {
		return err
	}
	defer active.Close()
	r.logRuntimeStarted(startup)
	return r.serveRuntime(ctx, active, startedAt)
}
