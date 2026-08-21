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
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type runtimeHealth struct {
	config     config.Config
	out        io.Writer
	policy     *policyRuntime
	management *managementRuntime
	sensor     *sensorRuntime
	profiles   *domainprocess.Profiles
}

func newRuntimeHealth(cfg config.Config, out io.Writer, policy *policyRuntime, management *managementRuntime, sensor *sensorRuntime) runtimeHealth {
	return runtimeHealth{config: cfg, out: out, policy: policy, management: management, sensor: sensor, profiles: management.processProfiles}
}

func (r runtimeHealth) reportSensorDegraded(stage string, err error) {
	if r.out != nil {
		fmt.Fprintf(r.out, "agent sensor degraded: stage=%s error=%v; retrying in background\n", stage, err)
	}
}

func (r runtimeHealth) reportStartupFailure(stage string, startupErr error) {
	if startupErr == nil {
		return
	}
	if r.out != nil {
		fmt.Fprintf(r.out, "agent startup failure: stage=%s error=%q\n", stage, startupErr)
	}
}

func (r runtimeHealth) collect(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) agenthealth.AgentHealth {
	snapshot := r.snapshot(ctx, rt, bus, batcher, sender, startedAt)
	return contractadapter.AgentHealth(snapshot)
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
	return contractadapter.SensorCapability(r.sensor.domainCapability())
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
