package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type startupFailure func(string, error) error

type runtimeStartup struct {
	sensor        *sensorruntime.Manager
	capability    contract.Capability
	intent        contract.CollectionIntent
	policy        policymodel.Policy
	telemetry     config.EffectiveTelemetry
	scopeType     string
	scopeSelector string
}

type activeRuntime struct {
	events      <-chan contract.EventEnvelope
	sensor      sensorruntime.Runtime
	bus         *telemetryadapter.Bus
	batcher     *telemetryadapter.Batcher
	sender      *telemetryadapter.RuntimeSender
	endpoint    *EndpointRuntime
	cancel      context.CancelFunc
	dataContext context.Context
	local       *LocalRuntime
	network     *networkSupervisor
	stopSensor  func()
}

func (r *Coordinator) healthRuntime() runtimeHealth {
	return newRuntimeHealth(r.Config, r.Out, &r.policyState, &r.managementState, &r.sensorState)
}

func (a *activeRuntime) Close() {
	if a.network != nil {
		a.network.Stop()
	}
	a.cancel()
	a.local.Close()
	a.stopSensor()
}

func (r *Coordinator) prepareRuntime(ctx context.Context, fail startupFailure) (runtimeStartup, error) {
	if stage, err := r.restoreManagementContext(ctx); err != nil {
		return runtimeStartup{}, fail(stage, err)
	}
	rt := sensorruntime.New(r.Sensor)
	capability, err := rt.Probe(ctx)
	if err != nil {
		capability = contract.Capability{Backend: r.Config.Sensor.Backend, Version: "unknown"}
		r.healthRuntime().reportSensorDegraded("probe", err)
	}
	r.sensorState.capability = capability
	intent, effectivePolicy, effectiveTelemetry, err := r.policyState.loadStartupPolicy(ctx)
	if err != nil {
		return runtimeStartup{}, fail("policy", err)
	}
	r.policyState.setEffectiveTelemetry(effectiveTelemetry)
	scope, err := r.Config.Sensor.EffectiveScope()
	if err != nil {
		return runtimeStartup{}, err
	}
	intent = policy.WithScope(intent, scope.Type, scope.Selector)
	r.policyState.setCollectionIntent(r.policyState.withCollectionCapabilities(intent))
	if err := r.policyState.applyStartupDetection(effectivePolicy); err != nil {
		return runtimeStartup{}, fail("detection", err)
	}
	return runtimeStartup{
		sensor: rt, capability: capability, intent: intent, policy: effectivePolicy,
		telemetry: effectiveTelemetry, scopeType: scope.Type, scopeSelector: scope.Selector,
	}, nil
}

func (r *Coordinator) restoreManagementContext(ctx context.Context) (string, error) {
	if r.managementState.localStore == nil {
		return "", nil
	}
	enrollment, err := r.managementState.localStore.Enrollment(ctx)
	if err != nil {
		return "enrollment", err
	}
	return "management_context", r.managementState.reconcileManagementContext(enrollment)
}

func (r *Coordinator) startRuntime(ctx context.Context, startup *runtimeStartup, startedAt time.Time, fail startupFailure) (*activeRuntime, error) {
	events, err := r.startSensor(ctx, *startup, fail)
	if err != nil {
		return nil, err
	}
	active, transport, err := r.startDataPlane(ctx, *startup, startedAt, fail)
	if err != nil {
		return nil, err
	}
	active.events = events
	if err := r.startNetwork(ctx, startup, active, transport, fail); err != nil {
		active.Close()
		return nil, err
	}
	r.policyState.applyRuntimePolicy(startup.policy)
	return active, nil
}

func (r *Coordinator) startSensor(ctx context.Context, startup runtimeStartup, fail startupFailure) (<-chan contract.EventEnvelope, error) {
	supervisor := sensorruntime.NewSubscriptionSupervisor(sensorruntime.AdaptManager(startup.sensor), startup.intent, sensorruntime.RetryOptions{})
	r.policyState.setSensorSupervisor(supervisor)
	endpointApplication := newEndpointPolicyApplication(&r.policyState, startup.sensor, nil)
	supervisor.OnApplied(endpointApplication.ResumeApplied)
	pendingIntent, hasPending, err := endpointApplication.PendingIntent(ctx)
	if err != nil {
		return nil, fail("pending_policy", err)
	}
	if hasPending {
		supervisor.UpdateIntent(pendingIntent)
	}
	supervisor.Start(ctx)
	return supervisor.Events(), nil
}

func (r *Coordinator) startDataPlane(ctx context.Context, startup runtimeStartup, startedAt time.Time, fail startupFailure) (*activeRuntime, *TransportRuntime, error) {
	appender, err := r.managementState.batchSender()
	if err != nil {
		return nil, nil, fail("data_plane", err)
	}
	bus := telemetryadapter.NewBus(startup.telemetry.MaxBatchItems * 16)
	if local, ok := appender.(*localStoreBatchSender); ok {
		local.onCommit = bus.PublishBatch
	}
	builder := r.telemetryState.newBatchBuilder()
	batcher := telemetryadapter.NewBatcher(builder.NewBatch, startup.telemetry.MaxBatchItems, startup.telemetry.FlushInterval, r.Config.Local.Export.MaxInflight*64, startup.telemetry.MaxBatchBytes)
	r.telemetryState.telemetryBatcher = batcher
	sender := telemetryadapter.NewRuntimeSender(batcher, appender, r.Config.Local.Export.RetryInitial, r.Config.Local.Export.RetryMax)
	localControl := localControlRuntime{
		config: r.Config, out: r.Out, policy: &r.policyState, management: &r.managementState,
		sensor: &r.sensorState,
	}
	stopLocal, err := localControl.start(ctx, startup.sensor, bus, batcher, sender, startedAt)
	if err != nil {
		return nil, nil, fail("local_control", err)
	}
	norm := r.startEventNormalizer(startup)
	dataCtx, cancel := context.WithCancel(ctx)
	active := &activeRuntime{
		sensor: startup.sensor, bus: bus, batcher: batcher, sender: sender,
		endpoint: NewEndpointRuntime(&r.policyState, norm, builder, r.learningDetector, r.processProfiles), cancel: cancel, local: NewLocalRuntime(stopLocal),
		dataContext: dataCtx,
	}
	active.stopSensor = idempotentSensorStop(startup.sensor)
	transport := NewTransportRuntime(transportRuntimeDependencies{
		config: r.Config, out: r.Out, sensorPort: r.Sensor, policy: &r.policyState,
		management: &r.managementState, sensorState: &r.sensorState,
	}, startup.sensor, bus, batcher, sender, startedAt, startup.scopeType, startup.scopeSelector)
	return active, transport, nil
}

func (r *Coordinator) startEventNormalizer(startup runtimeStartup) *eventadapter.EventNormalizer {
	identity := r.managementState.currentIdentity()
	norm := eventadapter.NewEventNormalizer(identity.AgentID, identity.HostID, eventadapter.EventNormalizerOptions{
		TenantID: identity.TenantID, ScopeType: startup.scopeType, ScopeSelector: startup.scopeSelector,
		Labels: r.telemetryState.runtimeLabels(startup.scopeType, startup.scopeSelector, startup.capability.Backend), InitialSequence: r.telemetryState.eventSeq,
	}, r.processProfiles)
	r.managementState.setNormalizer(norm)
	return norm
}

func idempotentSensorStop(sensor sensorruntime.Runtime) func() {
	stopped := false
	return func() {
		if stopped {
			return
		}
		stopped = true
		_ = sensor.Stop(context.Background())
	}
}

func (r *Coordinator) startNetwork(ctx context.Context, startup *runtimeStartup, active *activeRuntime, transport *TransportRuntime, fail startupFailure) error {
	if r.managementState.localStore == nil {
		go transport.RunDataFlow(active.dataContext)
		go transport.RunControlFlow(active.dataContext)
		return nil
	}
	go transport.RunDataFlow(active.dataContext)
	r.managementState.managedControl = transport
	r.managementState.network = newNetworkSupervisor(active.dataContext, transport.RunControlFlow, r.managementState.runManagedNetwork)
	active.network = r.managementState.network
	enrollment, err := r.managementState.localStore.Enrollment(ctx)
	if err != nil {
		return fail("enrollment", err)
	}
	if enrollment.State == sqlite.StateUnenrolling && enrollment.RevocationConfirmed {
		if err := r.finalizeStartupUnenrollment(ctx, startup, fail); err != nil {
			return err
		}
		enrollment, err = r.managementState.localStore.Enrollment(ctx)
		if err != nil {
			return fail("enrollment", err)
		}
	}
	return failIfError(fail, "management_context", r.managementState.reconcileManagementContext(enrollment))
}

func (r *Coordinator) finalizeStartupUnenrollment(ctx context.Context, startup *runtimeStartup, fail startupFailure) error {
	if err := r.managementState.configureEnrollmentCoordinator(ctx, startup.sensor).Resume(ctx); err != nil {
		return fail("unenrollment_finalize", err)
	}
	intent, effectivePolicy, effectiveTelemetry, err := r.policyState.loadStartupPolicy(ctx)
	if err != nil {
		return fail("standalone_policy", err)
	}
	startup.intent, startup.policy, startup.telemetry = intent, effectivePolicy, effectiveTelemetry
	r.policyState.setEffectiveTelemetry(effectiveTelemetry)
	return nil
}

func failIfError(fail startupFailure, stage string, err error) error {
	if err == nil {
		return nil
	}
	return fail(stage, err)
}

func (r *Coordinator) serveRuntime(ctx context.Context, active *activeRuntime, startedAt time.Time) error {
	ticker := time.NewTicker(r.Config.Health.Interval)
	defer ticker.Stop()
	tamper := &domainhealth.TamperDetector{}
	for {
		select {
		case <-ctx.Done():
			return r.finishRuntime(ctx.Err(), active, startedAt)
		case event, ok := <-active.events:
			if !ok {
				return r.finishRuntime(nil, active, startedAt)
			}
			if err := r.handleRuntimeEvent(event, active); err != nil {
				return err
			}
		case <-ticker.C:
			if err := r.handleHealthTick(ctx, active, startedAt, tamper); err != nil {
				return err
			}
		}
	}
}

func (r *Coordinator) finishRuntime(result error, active *activeRuntime, startedAt time.Time) error {
	drainErr := r.shutdownAndReport(context.Background(), active.sensor, active.bus, active.batcher, active.sender, startedAt, active.cancel, active.stopSensor)
	if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
		return drainErr
	}
	return result
}

func (r *Coordinator) handleRuntimeEvent(event contract.EventEnvelope, active *activeRuntime) error {
	batch, err := active.endpoint.ProcessEvent(event)
	if err != nil {
		return err
	}
	r.publishRuntimeBatch(batch, active)
	if r.Out != nil {
		fmt.Fprintf(r.Out, "agent runtime event: behavior=%s raw_ref=%s telemetry_events=%d telemetry_signals=%d\n", event.SensorEvent.GetBehavior(), event.RawRef, len(batch.GetEvents()), len(batch.GetSignals()))
	}
	return nil
}

func (r *Coordinator) handleHealthTick(ctx context.Context, active *activeRuntime, startedAt time.Time, tamper *domainhealth.TamperDetector) error {
	snapshot := r.healthRuntime().snapshot(ctx, active.sensor, active.bus, active.batcher, active.sender, startedAt)
	health := contractadapter.AgentHealth(snapshot)
	if err := r.publishTamperSignal(snapshot, active, tamper); err != nil {
		return err
	}
	r.logRuntimeHealth(health)
	return nil
}

func (r *Coordinator) publishTamperSignal(snapshot domainhealth.Snapshot, active *activeRuntime, tamper *domainhealth.TamperDetector) error {
	signal := tamper.Evaluate(snapshot, time.Now().UTC(), domainhealth.TamperOptions{
		MaxRestarts: uint64(r.Config.Sensor.MaxRestarts), MaxParseErrors: r.Config.Sensor.MaxParseErrors,
		MaxDroppedEvents: r.Config.Sensor.MaxDroppedEvents,
	})
	if signal == nil {
		return nil
	}
	wireSignal := contractadapter.Signal(*signal)
	batch, err := active.endpoint.ProcessSignals([]*signalv1.Signal{wireSignal})
	if err != nil {
		return err
	}
	r.publishRuntimeBatch(batch, active)
	if r.Out != nil {
		fmt.Fprintf(r.Out, "agent tamper signal: name=%s reason=%q\n", wireSignal.GetName(), wireSignal.GetEvidence().GetSummary())
	}
	return nil
}

func (r *Coordinator) publishRuntimeBatch(batch *dataplanev1.DataBatch, active *activeRuntime) {
	if r.managementState.localStore == nil {
		active.bus.PublishBatch(batch)
	}
	active.batcher.Add(batch)
}

func (r *Coordinator) logRuntimeStarted(startup runtimeStartup) {
	if r.Out == nil {
		return
	}
	identity := r.managementState.currentIdentity()
	fmt.Fprintf(r.Out, "agent runtime started: agent=%s host=%s tenant=%s sensor=%s version=%s behaviors=%d policy=%s version=%d mode=%s\n",
		identity.AgentID, identity.HostID, identity.TenantID, startup.capability.Backend, startup.capability.Version,
		len(startup.intent.Behaviors), startup.policy.PolicyID, startup.policy.Version, startup.policy.Mode)
}

func (r *Coordinator) logRuntimeHealth(health agenthealth.AgentHealth) {
	if r.Out == nil {
		return
	}
	fmt.Fprintf(r.Out, "agent health: sensor=%s running=%t policy_loaded=%t events_seen=%d queued_batches=%d dropped_batches=%d last_batcher_error=%q last_data_plane_error=%q\n",
		health.Sensor.Backend, health.Sensor.Running, health.Sensor.PolicyLoaded, health.Sensor.EventsSeen,
		health.TelemetryBatcher.QueuedBatches, health.TelemetryBatcher.DroppedBatches,
		health.TelemetryBatcher.LastError, health.TelemetrySender.LastError)
}
