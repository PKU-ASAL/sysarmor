package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/tamper"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
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
	telemetryBatcher        *telemetry.Batcher
	managedControl          *TransportRuntime
	sensorSupervisor        *sensorruntime.SubscriptionSupervisor
	pendingEndpoint         *agentcontrol.PreparedEndpointPolicy
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
	signalSeq               uint64
	telemetrySeq            uint64
}

func (r *AgentRuntime) withDetectionUpdateTransaction(fn func()) {
	r.detectionUpdateMu.Lock()
	defer r.detectionUpdateMu.Unlock()
	fn()
}

func New(cfg config.Config) (*AgentRuntime, error) {
	featureFlags, err := applyRuntimeFeatureFlags(cfg)
	if err != nil {
		return nil, err
	}
	sensor, err := sensorFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	contentStore, err := newContentStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("load startup content: %w", err)
	}
	var state *localstore.Store
	if cfg.Manager.Transport == "" {
		state, err = localstore.Open(context.Background(), localstore.Options{RootDir: cfg.Local.StatePath, MaxBytes: cfg.Local.Storage.MaxBytes, MinFreeBytes: cfg.Local.Storage.MinFreeBytes, SegmentSize: cfg.Local.Storage.SegmentSize, SignalMaxCount: cfg.Local.Storage.SignalMaxCount})
		if err != nil {
			return nil, fmt.Errorf("open agent local store: %w", err)
		}
		identity, err := state.DeviceIdentity(context.Background())
		if err != nil {
			_ = state.Close()
			return nil, fmt.Errorf("load device identity: %w", err)
		}
		if cfg.Agent.ID == "" {
			cfg.Agent.ID = identity.DeviceID
		}
		if cfg.Agent.HostID == "" {
			cfg.Agent.HostID = identity.HostID
		}
		if cfg.Agent.TenantID == "" {
			cfg.Agent.TenantID = "local"
		}
		cursor, err := state.SequenceCursor(context.Background())
		if err != nil {
			_ = state.Close()
			return nil, fmt.Errorf("load local sequence cursor: %w", err)
		}
		runtime := &AgentRuntime{Config: cfg, Sensor: sensor, content: contentStore, featureFlags: featureFlags, localStore: state, eventSeq: cursor.Event, signalSeq: cursor.Signal}
		runtime.setRuntimeIdentity(runtimeIdentity{AgentID: cfg.Agent.ID, HostID: cfg.Agent.HostID, TenantID: cfg.Agent.TenantID})
		return runtime, nil
	}
	runtime := &AgentRuntime{Config: cfg, Sensor: sensor, content: contentStore, featureFlags: featureFlags, localStore: state}
	runtime.setRuntimeIdentity(runtimeIdentity{AgentID: cfg.Agent.ID, HostID: cfg.Agent.HostID, TenantID: cfg.Agent.TenantID})
	return runtime, nil
}

func NewAgentRuntime(cfg config.Config) (*AgentRuntime, error) {
	return New(cfg)
}

func (r *AgentRuntime) Run(ctx context.Context, opts Options) error {
	if r.localStore != nil {
		defer r.localStore.Close()
	}
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
	endpointControl := agentcontrol.NewEndpointPolicyController(newEndpointPolicyRuntime(r, rt, nil))
	sensorSupervisor.OnApplied(endpointControl.CompletePending)
	pending, hasPending, err := endpointControl.LoadPending(ctx)
	if err != nil {
		return failStartup("pending_policy", err)
	}
	if hasPending {
		newEndpointPolicyRuntime(r, rt, nil).SetPendingEndpointPolicy(pending)
		sensorSupervisor.UpdateIntent(pending.Intent)
	}
	sensorSupervisor.Start(ctx)
	events := sensorSupervisor.Events()
	appender, err := r.batchSender()
	if err != nil {
		return failStartup("data_plane", err)
	}
	bus := telemetry.NewBus(effectiveTelemetry.MaxBatchItems * 16)
	if local, ok := appender.(*localStoreBatchSender); ok {
		local.onCommit = bus.PublishBatch
	}
	batcher := telemetry.NewBatcher(r.newDataBatch, effectiveTelemetry.MaxBatchItems, effectiveTelemetry.FlushInterval, r.Config.Local.Export.MaxInflight*64, effectiveTelemetry.MaxBatchBytes)
	r.telemetryBatcher = batcher
	sender := &telemetry.Sender{
		Appender:     appender,
		Batcher:      batcher,
		RetryInitial: r.Config.Local.Export.RetryInitial,
		RetryMax:     r.Config.Local.Export.RetryMax,
	}
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
	endpointRuntime := NewEndpointRuntime(r, norm)
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
