package runtime

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	applicationhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/health"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
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

type runtimeHealth struct {
	config     config.Config
	out        io.Writer
	policy     *policyRuntime
	management *managementRuntime
	telemetry  *telemetryRuntime
	sensor     *sensorRuntime
}

func newRuntimeHealth(cfg config.Config, out io.Writer, policy *policyRuntime, management *managementRuntime, telemetry *telemetryRuntime, sensor *sensorRuntime) runtimeHealth {
	return runtimeHealth{config: cfg, out: out, policy: policy, management: management, telemetry: telemetry, sensor: sensor}
}

func (r runtimeHealth) reportSensorDegraded(stage string, err error) {
	if r.out != nil {
		fmt.Fprintf(r.out, "agent sensor degraded: stage=%s error=%v; retrying in background\n", stage, err)
	}
}

func (r runtimeHealth) reportStartupFailure(reporter healthReporter, startedAt time.Time, stage string, startupErr error) {
	if reporter == nil || startupErr == nil {
		return
	}
	identity := r.management.currentIdentity()
	health := agenthealth.AgentHealth{
		AgentID:       identity.AgentID,
		HostID:        identity.HostID,
		TenantID:      identity.TenantID,
		Scope:         r.runtimeScope(),
		Status:        "degraded",
		PolicyID:      r.policy.activePolicy().PolicyID,
		PolicyVersion: r.policy.activePolicy().Version,
		PolicyMode:    r.policyMode(),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		ObservedAt:    time.Now().UTC(),
		Sensor: agenthealth.SensorHealth{
			Backend:      r.config.Sensor.Backend,
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
	if err := reporter.Report(context.Background(), health); err != nil && r.out != nil {
		fmt.Fprintf(r.out, "agent startup health report error: %v\n", err)
	}
	if r.out != nil {
		fmt.Fprintf(r.out, "agent startup failure: stage=%s error=%q\n", stage, startupErr)
	}
}

func (r runtimeHealth) reporter() healthReporter {
	return localHealthReporter{}
}

func (r runtimeHealth) collect(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) (agenthealth.AgentHealth, error) {
	snapshot := r.snapshot(ctx, rt, bus, batcher, sender, startedAt)
	return contractadapter.AgentHealth(snapshot), nil
}

func (r runtimeHealth) snapshot(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) domainhealth.Snapshot {
	return applicationhealth.NewService(newRuntimeHealthSource(r, rt, bus, batcher, sender, startedAt)).Snapshot(ctx)
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

func (r runtimeHealth) runtimeCapability() agenthealth.SensorCapability {
	collection := make([]agenthealth.CollectionBehaviorCapability, 0, len(r.sensor.capability.Collection))
	for _, behavior := range r.sensor.capability.Collection {
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
		Backend:         r.sensor.capability.Backend,
		Version:         r.sensor.capability.Version,
		SupportsExec:    r.sensor.capability.SupportsExec,
		SupportsConnect: r.sensor.capability.SupportsConnect,
		SupportsFile:    r.sensor.capability.SupportsFile,
		SupportsEnforce: r.sensor.capability.SupportsEnforce,
		SupportsHealth:  r.sensor.capability.SupportsHealth,
		KernelRelease:   r.sensor.capability.KernelRelease,
		BTFAvailable:    r.sensor.capability.BTFAvailable,
		BPFFSAvailable:  r.sensor.capability.BPFFSAvailable,
		Collection:      collection,
	}
}

func (r runtimeHealth) runtimeScope() agenthealth.RuntimeScope {
	scope, err := r.config.Sensor.EffectiveScope()
	if err != nil {
		return agenthealth.RuntimeScope{Type: "host"}
	}
	return agenthealth.RuntimeScope{Type: scope.Type, Selector: scope.Selector}
}

func (r runtimeHealth) policyMode() string {
	if mode := r.policy.activePolicy().Mode; mode != "" {
		return mode
	}
	if r.config.Sensor.ObserveOnly {
		return "observe"
	}
	return "enforce"
}

func (r runtimeHealth) detectionHealth() agenthealth.DetectionHealth {
	r.policy.mu.RLock()
	defer r.policy.mu.RUnlock()
	health := r.policy.detectionStatus
	health.FeatureFlags = r.policy.featureFlags
	return health
}
