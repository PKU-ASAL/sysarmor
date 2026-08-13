package daemon

import (
	"context"
	"fmt"
	"time"

	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type localHealthReporter struct{}

func (localHealthReporter) Report(context.Context, agenthealth.AgentHealth) error {
	return nil
}

type healthReporter interface {
	Report(context.Context, agenthealth.AgentHealth) error
}

func (r *AgentRuntime) reportSensorDegraded(stage string, err error) {
	if r.Out != nil {
		fmt.Fprintf(r.Out, "agent sensor degraded: stage=%s error=%v; retrying in background\n", stage, err)
	}
}

func (r *AgentRuntime) reportStartupFailure(reporter healthReporter, startedAt time.Time, stage string, startupErr error) {
	if reporter == nil || startupErr == nil {
		return
	}
	identity := r.currentIdentity()
	health := agenthealth.AgentHealth{
		AgentID:       identity.AgentID,
		HostID:        identity.HostID,
		TenantID:      identity.TenantID,
		Scope:         r.runtimeScope(),
		Status:        "degraded",
		PolicyID:      r.activePolicy().PolicyID,
		PolicyVersion: r.activePolicy().Version,
		PolicyMode:    r.policyMode(),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		ObservedAt:    time.Now().UTC(),
		Sensor: agenthealth.SensorHealth{
			Backend:      r.Config.Sensor.Backend,
			Installed:    false,
			Running:      false,
			PolicyLoaded: false,
			LastError:    fmt.Sprintf("%s: %v", stage, startupErr),
		},
		Capability:       r.runtimeCapability(),
		TelemetryBus:     agenthealth.TelemetryBusHealth{},
		TelemetryBatcher: agenthealth.TelemetryBatcherHealth{},
		TelemetrySender:  agenthealth.TelemetrySenderHealth{},
	}
	if err := reporter.Report(context.Background(), health); err != nil && r.Out != nil {
		fmt.Fprintf(r.Out, "agent startup health report error: %v\n", err)
	}
	if r.Out != nil {
		fmt.Fprintf(r.Out, "agent startup failure: stage=%s error=%q\n", stage, startupErr)
	}
}

func (r *AgentRuntime) healthReporter() healthReporter {
	return localHealthReporter{}
}

func (r *AgentRuntime) collectHealth(ctx context.Context, rt sensorruntime.Runtime, source any, rest ...any) (agenthealth.AgentHealth, error) {
	bus, batcher, sender, startedAt := r.healthTelemetryArgs(source, rest...)
	supervisor := r.currentSensorSupervisor()
	var supervisorStatus *sensorruntime.SupervisorStatus
	if supervisor != nil {
		status := supervisor.Status()
		supervisorStatus = &status
	}
	sensor, healthErr := rt.Health(ctx)
	sensor, err := resolveSensorHealth(sensor, healthErr, supervisorStatus, r.Config.Sensor.Backend)
	if err != nil {
		return agenthealth.AgentHealth{}, err
	}
	busStats := bus.Stats()
	batcherStats := batcher.Stats()
	senderStats := sender.Stats()
	status := "ok"
	if !sensor.Running || sensor.LastError != "" || batcherStats.LastError != "" || senderStats.LastError != "" {
		status = "degraded"
	}
	if batcherStats.DroppedBatches > 0 || busStats.EventDropped > 0 || busStats.SignalDropped > 0 {
		status = "degraded"
	}
	if r.Config.Sensor.MaxParseErrors > 0 && sensor.ParseErrors > r.Config.Sensor.MaxParseErrors {
		status = "degraded"
	}
	if r.Config.Sensor.MaxDroppedEvents > 0 && sensor.EventsDropped > r.Config.Sensor.MaxDroppedEvents {
		status = "degraded"
	}
	cepMetrics := r.currentDetection().Metrics()
	cepDegraded := cepMetrics.EvictedCEPGroups > 0 || cepMetrics.DroppedEventRefs > 0 || cepMetrics.CEPEvalErrors > 0
	if cepDegraded {
		status = "degraded"
	}
	pendingPolicy, err := r.pendingPolicyStatus(ctx)
	if err != nil {
		return agenthealth.AgentHealth{}, err
	}
	if pendingPolicy.Status != "" {
		status = "degraded"
	}
	now := time.Now().UTC()
	identity := r.currentIdentity()
	return agenthealth.AgentHealth{
		AgentID:       identity.AgentID,
		HostID:        identity.HostID,
		TenantID:      identity.TenantID,
		Scope:         r.runtimeScope(),
		Status:        status,
		PolicyID:      r.activePolicy().PolicyID,
		PolicyVersion: r.activePolicy().Version,
		PolicyMode:    r.policyMode(),
		PendingPolicy: pendingPolicy,
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		ObservedAt:    now,
		Sensor: agenthealth.SensorHealth{
			Backend:        sensor.Backend,
			Installed:      sensor.Installed,
			Running:        sensor.Running,
			Version:        sensor.Version,
			PolicyLoaded:   sensor.PolicyLoaded,
			EventsSeen:     sensor.EventsSeen,
			EventsDropped:  sensor.EventsDropped,
			ParseErrors:    sensor.ParseErrors,
			RestartCount:   sensor.RestartCount,
			LastEventAt:    sensor.LastEventAt,
			LastExitReason: sensor.LastExitReason,
			LastError:      sensor.LastError,
		},
		Capability: r.runtimeCapability(),
		TelemetryBus: agenthealth.TelemetryBusHealth{
			EventCapacity:     busStats.EventCapacity,
			EventBuffered:     busStats.EventBuffered,
			EventDropped:      busStats.EventDropped,
			EventSubscribers:  busStats.EventSubscribers,
			SignalCapacity:    busStats.SignalCapacity,
			SignalBuffered:    busStats.SignalBuffered,
			SignalDropped:     busStats.SignalDropped,
			SignalSubscribers: busStats.SignalSubscribers,
		},
		TelemetryBatcher: agenthealth.TelemetryBatcherHealth{
			PendingEvents:     batcherStats.PendingEvents,
			PendingSignals:    batcherStats.PendingSignals,
			QueuedBatches:     batcherStats.QueuedBatches,
			QueueCapacity:     batcherStats.QueueCapacity,
			DroppedBatches:    batcherStats.DroppedBatches,
			DroppedEvents:     batcherStats.DroppedEvents,
			DroppedSignals:    batcherStats.DroppedSignals,
			FlushedBatches:    batcherStats.FlushedBatches,
			FlushedEvents:     batcherStats.FlushedEvents,
			FlushedSignals:    batcherStats.FlushedSignals,
			PendingBytes:      batcherStats.PendingBytes,
			MaxBytes:          batcherStats.MaxBytes,
			FlushedByCount:    batcherStats.FlushedByCount,
			FlushedByBytes:    batcherStats.FlushedByBytes,
			FlushedByInterval: batcherStats.FlushedByInterval,
			FlushedByShutdown: batcherStats.FlushedByShutdown,
			LastFlushReason:   batcherStats.LastFlushReason,
			Closed:            batcherStats.Closed,
			LastError:         batcherStats.LastError,
		},
		TelemetrySender: agenthealth.TelemetrySenderHealth{
			SentBatches:     senderStats.SentBatches,
			SentEvents:      senderStats.SentEvents,
			SentSignals:     senderStats.SentSignals,
			RejectedBatches: senderStats.RejectedBatches,
			RetriedBatches:  senderStats.RetriedBatches,
			Drained:         senderStats.Drained,
			LastError:       senderStats.LastError,
		},
		Detection: r.detectionHealth(),
		CEP: agenthealth.CEPHealth{
			ActiveGroups:     cepMetrics.ActiveCEPGroups,
			EvictedGroups:    cepMetrics.EvictedCEPGroups,
			ExpiredGroups:    cepMetrics.ExpiredCEPGroups,
			DroppedEventRefs: cepMetrics.DroppedEventRefs,
			EvalErrors:       cepMetrics.CEPEvalErrors,
			EmittedSignals:   cepMetrics.EmittedSignals,
			Degraded:         cepDegraded,
		},
		Streams: agenthealth.LocalStreamHealth{
			EventCapacity:        busStats.EventCapacity,
			EventBuffered:        busStats.EventBuffered,
			EventNextSequence:    busStats.EventNextSequence,
			EventOldestSequence:  busStats.EventOldestSequence,
			EventNewestSequence:  busStats.EventNewestSequence,
			EventEvicted:         busStats.EventDropped,
			EventSubscribers:     busStats.EventSubscribers,
			SignalCapacity:       busStats.SignalCapacity,
			SignalBuffered:       busStats.SignalBuffered,
			SignalNextSequence:   busStats.SignalNextSequence,
			SignalOldestSequence: busStats.SignalOldestSequence,
			SignalNewestSequence: busStats.SignalNewestSequence,
			SignalEvicted:        busStats.SignalDropped,
			SignalSubscribers:    busStats.SignalSubscribers,
		},
	}, nil
}

func (r *AgentRuntime) currentSensorSupervisor() *sensorruntime.SubscriptionSupervisor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sensorSupervisor
}

func applySupervisorHealth(sensor contract.Health, status sensorruntime.SupervisorStatus) contract.Health {
	sensor.RestartCount += status.RestartCount
	if status.State == "degraded" {
		sensor.Running = false
		sensor.LastError = status.LastError
	}
	return sensor
}

func resolveSensorHealth(sensor contract.Health, healthErr error, status *sensorruntime.SupervisorStatus, backend string) (contract.Health, error) {
	if healthErr != nil && status == nil {
		return contract.Health{}, healthErr
	}
	if healthErr != nil {
		sensor.Backend = backend
		sensor.LastError = healthErr.Error()
	}
	if status != nil {
		sensor = applySupervisorHealth(sensor, *status)
		if healthErr != nil {
			sensor.LastError += "; health: " + healthErr.Error()
		}
	}
	return sensor, nil
}

func (r *AgentRuntime) healthTelemetryArgs(source any, rest ...any) (*telemetryadapter.Bus, *telemetryadapter.Batcher, *telemetryadapter.RuntimeSender, time.Time) {
	bus, _ := source.(*telemetryadapter.Bus)
	var batcher *telemetryadapter.Batcher
	var sender *telemetryadapter.RuntimeSender
	var startedAt time.Time
	if bus != nil {
		if len(rest) > 0 {
			batcher, _ = rest[0].(*telemetryadapter.Batcher)
		}
		if len(rest) > 1 {
			sender, _ = rest[1].(*telemetryadapter.RuntimeSender)
		}
		if len(rest) > 2 {
			startedAt, _ = rest[2].(time.Time)
		}
	}
	if bus == nil {
		bus = telemetryadapter.NewBus(r.Config.Telemetry.MaxBatchItems * 16)
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

func (r *AgentRuntime) runtimeCapability() agenthealth.SensorCapability {
	collection := make([]agenthealth.CollectionBehaviorCapability, 0, len(r.capability.Collection))
	for _, behavior := range r.capability.Collection {
		collection = append(collection, agenthealth.CollectionBehaviorCapability{
			Behavior:             behavior.Behavior,
			SensorMapping:        behavior.SensorMapping,
			Fields:               append([]string(nil), behavior.Fields...),
			PushdownSelectors:    append([]string(nil), behavior.PushdownSelectors...),
			AgentSideSelectors:   append([]string(nil), behavior.AgentSideSelectors...),
			UnsupportedSelectors: append([]string(nil), behavior.UnsupportedSelectors...),
		})
	}
	return agenthealth.SensorCapability{
		Backend:         r.capability.Backend,
		Version:         r.capability.Version,
		SupportsExec:    r.capability.SupportsExec,
		SupportsConnect: r.capability.SupportsConnect,
		SupportsFile:    r.capability.SupportsFile,
		SupportsEnforce: r.capability.SupportsEnforce,
		SupportsHealth:  r.capability.SupportsHealth,
		KernelRelease:   r.capability.KernelRelease,
		BTFAvailable:    r.capability.BTFAvailable,
		BPFFSAvailable:  r.capability.BPFFSAvailable,
		Collection:      collection,
	}
}

func (r *AgentRuntime) runtimeScope() agenthealth.RuntimeScope {
	scope, err := r.Config.Sensor.EffectiveScope()
	if err != nil {
		return agenthealth.RuntimeScope{Type: "host"}
	}
	return agenthealth.RuntimeScope{Type: scope.Type, Selector: scope.Selector}
}

func (r *AgentRuntime) policyMode() string {
	if mode := r.activePolicy().Mode; mode != "" {
		return mode
	}
	if r.Config.Sensor.ObserveOnly {
		return "observe"
	}
	return "enforce"
}

func (r *AgentRuntime) detectionHealth() agenthealth.DetectionHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	health := r.detectionStatus
	health.FeatureFlags = r.featureFlags
	return health
}
