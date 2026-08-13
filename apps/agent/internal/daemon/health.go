package daemon

import (
	"context"
	"fmt"
	"time"

	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	applicationhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/health"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
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
	snapshot := r.collectHealthSnapshot(ctx, rt, source, rest...)
	return contractadapter.AgentHealth(snapshot), nil
}

func (r *AgentRuntime) collectHealthSnapshot(ctx context.Context, rt sensorruntime.Runtime, source any, rest ...any) domainhealth.Snapshot {
	bus, batcher, sender, startedAt := r.healthTelemetryArgs(source, rest...)
	return applicationhealth.NewService(newRuntimeHealthSource(r, rt, bus, batcher, sender, startedAt)).Snapshot(ctx)
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
