package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/tamper"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Options struct {
	Out io.Writer
}

type AgentRuntime struct {
	Config                  config.Config
	Sensor                  contract.Sensor
	Out                     io.Writer
	capability              contract.Capability
	localStore              *localstore.Store
	network                 *networkSupervisor
	mu                      sync.RWMutex
	detectionUpdateMu       sync.Mutex
	enrollmentCoordinatorMu sync.Mutex
	enrollmentCoordinator   *enrollmentCoordinator
	completionReporter      *unenrollmentCompletionReporter
	policyAuthorityMu       sync.RWMutex
	identity                runtimeIdentity
	standaloneIdentity      runtimeIdentity
	normalizer              *eventadapter.EventNormalizer
	telemetryBatcher        *telemetryadapter.Batcher
	managedControl          *TransportRuntime
	sensorSupervisor        *sensorruntime.SubscriptionSupervisor
	revokeEnrollment        func(context.Context, localstore.Enrollment, string) (string, time.Time, error)
	reportUnenrollment      func(context.Context) (bool, error)
	endpointPolicy          policy.EndpointPolicy
	effectiveTelemetry      config.EffectiveTelemetry
	policy                  policymodel.Policy
	detection               *detection.Engine
	collection              contract.CollectionIntent
	content                 *agentcontent.Store
	featureFlags            agenthealth.RuntimeFeatureFlags
	detectionStatus         agenthealth.DetectionHealth
	eventSeq                uint64
	initialSignalSequence   uint64
	telemetrySeq            uint64
	policyController        PolicyControllerFactory
}

type Dependencies struct {
	Config       config.Config
	Sensor       contract.Sensor
	Content      *agentcontent.Store
	LocalStore   *localstore.Store
	FeatureFlags agenthealth.RuntimeFeatureFlags
	EventSeq     uint64
	SignalSeq    uint64
	Policy       PolicyControllerFactory
}

type PolicyControllerFactory func(*AgentRuntime, sensorruntime.Runtime, *telemetryadapter.Batcher) *agentcontrol.ApplicationPolicyController

func (r *AgentRuntime) withDetectionUpdateTransaction(fn func()) {
	r.detectionUpdateMu.Lock()
	defer r.detectionUpdateMu.Unlock()
	fn()
}

func NewRuntime(dependencies Dependencies) (*AgentRuntime, error) {
	if dependencies.Sensor == nil {
		return nil, fmt.Errorf("daemon sensor dependency is required")
	}
	if dependencies.Content == nil {
		return nil, fmt.Errorf("daemon content dependency is required")
	}
	if dependencies.Policy == nil {
		return nil, fmt.Errorf("daemon policy controller factory is required")
	}
	runtime := &AgentRuntime{
		Config: dependencies.Config, Sensor: dependencies.Sensor, content: dependencies.Content,
		featureFlags: dependencies.FeatureFlags, localStore: dependencies.LocalStore,
		eventSeq: dependencies.EventSeq, initialSignalSequence: dependencies.SignalSeq,
	}
	runtime.policyController = dependencies.Policy
	runtime.setRuntimeIdentity(runtimeIdentity{
		AgentID:  dependencies.Config.Agent.ID,
		HostID:   dependencies.Config.Agent.HostID,
		TenantID: dependencies.Config.Agent.TenantID,
	})
	return runtime, nil
}

func (r *AgentRuntime) Run(ctx context.Context, opts Options) error {
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
	if r.localStore != nil {
		enrollment, err := r.localStore.Enrollment(ctx)
		if err != nil {
			return failStartup("enrollment", err)
		}
		if err := r.reconcileManagementContext(enrollment); err != nil {
			return failStartup("management_context", err)
		}
	}
	rt := sensorruntime.New(r.Sensor)
	capability, err := rt.Probe(ctx)
	if err != nil {
		capability = contract.Capability{Backend: r.Config.Sensor.Backend, Version: "unknown"}
		r.reportSensorDegraded("probe", err)
	}
	r.capability = capability
	intent, effectivePolicy, effectiveTelemetry, err := r.loadStartupPolicy(ctx)
	if err != nil {
		return failStartup("policy", err)
	}
	r.setEffectiveTelemetry(effectiveTelemetry)
	scope, err := r.Config.Sensor.EffectiveScope()
	if err != nil {
		return err
	}
	scopeType := scope.Type
	scopeSelector := scope.Selector
	intent = policy.WithScope(intent, scopeType, scopeSelector)
	r.setCollectionIntent(r.withCollectionCapabilities(intent))
	if err := r.applyStartupDetection(effectivePolicy); err != nil {
		return failStartup("detection", err)
	}
	longControl := r.Config.Manager.Transport == "grpc"
	sensorSupervisor := sensorruntime.NewSubscriptionSupervisor(sensorruntime.AdaptManager(rt), intent, sensorruntime.RetryOptions{})
	r.setSensorSupervisor(sensorSupervisor)
	endpointApplication := newEndpointPolicyApplication(r, rt, nil)
	sensorSupervisor.OnApplied(endpointApplication.ResumeApplied)
	pendingIntent, hasPending, err := endpointApplication.PendingIntent(ctx)
	if err != nil {
		return failStartup("pending_policy", err)
	}
	if hasPending {
		sensorSupervisor.UpdateIntent(pendingIntent)
	}
	sensorSupervisor.Start(ctx)
	events := sensorSupervisor.Events()
	appender, err := r.batchSender()
	if err != nil {
		return failStartup("data_plane", err)
	}
	bus := telemetryadapter.NewBus(effectiveTelemetry.MaxBatchItems * 16)
	if local, ok := appender.(*localStoreBatchSender); ok {
		local.onCommit = bus.PublishBatch
	}
	batchBuilder := telemetryadapter.NewBatchBuilder(r, r.initialSignalSequence)
	batcher := telemetryadapter.NewBatcher(batchBuilder.NewBatch, effectiveTelemetry.MaxBatchItems, effectiveTelemetry.FlushInterval, r.Config.Local.Export.MaxInflight*64, effectiveTelemetry.MaxBatchBytes)
	r.telemetryBatcher = batcher
	sender := telemetryadapter.NewRuntimeSender(batcher, appender, r.Config.Local.Export.RetryInitial, r.Config.Local.Export.RetryMax)
	stopLocalControl, err := r.startLocalControlServer(ctx, rt, bus, batcher, sender, startedAt)
	if err != nil {
		return failStartup("local_control", err)
	}
	localRuntime := NewLocalRuntime(stopLocalControl)
	defer localRuntime.Close()
	dataPlaneCtx, cancelDataPlane := context.WithCancel(ctx)
	defer cancelDataPlane()
	identity := r.currentIdentity()
	norm := eventadapter.NewEventNormalizer(identity.AgentID, identity.HostID, eventadapter.EventNormalizerOptions{
		TenantID:        identity.TenantID,
		ScopeType:       scopeType,
		ScopeSelector:   scopeSelector,
		Labels:          r.runtimeLabels(scopeType, scopeSelector, capability.Backend),
		InitialSequence: r.eventSeq,
	})
	r.setNormalizer(norm)
	endpointRuntime := NewEndpointRuntime(r, norm, batchBuilder)
	transportRuntime := NewTransportRuntime(r, rt, bus, batcher, sender, startedAt, scopeType, scopeSelector)
	if r.localStore != nil {
		go transportRuntime.RunDataFlow(dataPlaneCtx)
		r.managedControl = transportRuntime
		r.network = newNetworkSupervisor(dataPlaneCtx, transportRuntime.RunControlFlow, r.runManagedNetwork)
		enrollment, err := r.localStore.Enrollment(ctx)
		if err != nil {
			return failStartup("enrollment", err)
		}
		if enrollment.State == localstore.StateUnenrolling && enrollment.RevocationConfirmed {
			if err := r.configureEnrollmentCoordinator(ctx, rt).Resume(ctx); err != nil {
				return failStartup("unenrollment_finalize", err)
			}
			intent, effectivePolicy, effectiveTelemetry, err = r.loadStartupPolicy(ctx)
			if err != nil {
				return failStartup("standalone_policy", err)
			}
			r.setEffectiveTelemetry(effectiveTelemetry)
			enrollment, err = r.localStore.Enrollment(ctx)
			if err != nil {
				return failStartup("enrollment", err)
			}
		}
		if err := r.reconcileManagementContext(enrollment); err != nil {
			return failStartup("management_context", err)
		}
		defer r.network.Stop()
	} else {
		go transportRuntime.RunDataFlow(dataPlaneCtx)
		go transportRuntime.RunControlFlow(dataPlaneCtx)
	}
	r.applyRuntimePolicy(effectivePolicy)
	if r.Out != nil {
		identity = r.currentIdentity()
		fmt.Fprintf(r.Out, "agent daemon started: agent=%s host=%s tenant=%s sensor=%s version=%s behaviors=%d policy=%s version=%d mode=%s\n",
			identity.AgentID, identity.HostID, identity.TenantID, capability.Backend, capability.Version, len(intent.Behaviors), effectivePolicy.PolicyID, effectivePolicy.Version, effectivePolicy.Mode)
	}

	ticker := time.NewTicker(r.Config.Health.Interval)
	defer ticker.Stop()
	tamperDetector := &tamper.Detector{}
	stopped := false
	stopRuntime := func() {
		if stopped {
			return
		}
		stopped = true
		_ = rt.Stop(context.Background())
	}
	defer stopRuntime()

	for {
		select {
		case <-ctx.Done():
			drainErr := r.shutdownAndReport(context.Background(), rt, bus, batcher, sender, reporter, startedAt, cancelDataPlane, stopRuntime)
			if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
				return drainErr
			}
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				drainErr := r.shutdownAndReport(context.Background(), rt, bus, batcher, sender, reporter, startedAt, cancelDataPlane, stopRuntime)
				if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
					return drainErr
				}
				return nil
			}
			batch, err := endpointRuntime.ProcessEvent(ev)
			if err != nil {
				return err
			}
			if r.localStore == nil {
				bus.PublishBatch(batch)
			}
			batcher.Add(batch)
			if r.Out != nil {
				fmt.Fprintf(r.Out, "agent daemon event: behavior=%s raw_ref=%s telemetry_events=%d telemetry_signals=%d\n", ev.SensorEvent.GetBehavior(), ev.RawRef, len(batch.GetEvents()), len(batch.GetSignals()))
			}
		case <-ticker.C:
			health, err := r.collectHealth(ctx, rt, bus, batcher, sender, startedAt)
			if err != nil {
				return err
			}
			if sig := tamperDetector.Evaluate(health, time.Now().UTC(), tamper.Options{
				MaxRestarts:      uint64(r.Config.Sensor.MaxRestarts),
				MaxParseErrors:   r.Config.Sensor.MaxParseErrors,
				MaxDroppedEvents: r.Config.Sensor.MaxDroppedEvents,
			}); sig != nil {
				batch, err := endpointRuntime.ProcessSignals([]*signalv1.Signal{sig})
				if err != nil {
					return err
				}
				if r.localStore == nil {
					bus.PublishBatch(batch)
				}
				batcher.Add(batch)
				if r.Out != nil {
					fmt.Fprintf(r.Out, "agent tamper signal: name=%s reason=%q\n", sig.GetName(), sig.GetEvidence().GetSummary())
				}
			}
			if !longControl {
				if err := reporter.Report(ctx, health); err != nil && r.Out != nil {
					fmt.Fprintf(r.Out, "agent health report error: %v\n", err)
				}
			}
			if r.Out != nil {
				fmt.Fprintf(r.Out, "agent health: sensor=%s running=%t policy_loaded=%t events_seen=%d queued_batches=%d dropped_batches=%d last_batcher_error=%q last_data_plane_error=%q\n",
					health.Sensor.Backend, health.Sensor.Running, health.Sensor.PolicyLoaded, health.Sensor.EventsSeen, health.TelemetryBatcher.QueuedBatches, health.TelemetryBatcher.DroppedBatches, health.TelemetryBatcher.LastError, health.TelemetrySender.LastError)
			}
		}
	}
}
