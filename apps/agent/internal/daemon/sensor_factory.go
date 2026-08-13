package daemon

import (
	"fmt"
	"os"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/fake"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func applyRuntimeFeatureFlags(cfg config.Config) (agenthealth.RuntimeFeatureFlags, error) {
	strategy := strings.ToLower(strings.TrimSpace(cfg.Runtime.FeatureFlags.MatcherStrategy))
	if strategy == "" {
		strategy = string(matcher.StrategyLinear)
	}
	if override := strings.TrimSpace(os.Getenv("SYSARMOR_TEST_MATCHER_STRATEGY")); override != "" {
		strategy = strings.ToLower(override)
	}
	switch matcher.Strategy(strategy) {
	case matcher.StrategyLinear, matcher.StrategyOptimized:
		matcher.SetDefaultStrategy(matcher.Strategy(strategy))
	default:
		return agenthealth.RuntimeFeatureFlags{}, fmt.Errorf("runtime.feature_flags.matcher_strategy: unsupported value %q", strategy)
	}
	return agenthealth.RuntimeFeatureFlags{MatcherStrategy: strategy}, nil
}

func sensorFromConfig(cfg config.Config) (contract.Sensor, error) {
	switch cfg.Sensor.Backend {
	case "fake":
		count := cfg.Sensor.FakeStartupEvents
		if count == 0 {
			count = 1
		}
		return fake.NewWithStartupEvents(count), nil
	case "tetragon":
		restart, err := tetragonRestartPolicy(cfg.Sensor)
		if err != nil {
			return nil, err
		}
		backend := tetragon.NewBackendWithOptions(cfg.Sensor.PolicyPath, cfg.Sensor.EventSource, cfg.Sensor.Version, tetragon.BundleConfig{
			BundleDir:    cfg.Sensor.BundleDir,
			InstallDir:   cfg.Sensor.InstallDir,
			TetraPath:    cfg.Sensor.TetraPath,
			TetragonPath: cfg.Sensor.TetragonPath,
		}, restart)
		backend.EventTransport = cfg.Sensor.EventTransport
		backend.ServerAddress = cfg.Sensor.ServerAddress
		backend.CgroupRate = cfg.Sensor.CgroupRate
		backend.PprofAddress = cfg.Sensor.PprofAddress
		backend.GopsAddress = cfg.Sensor.GopsAddress
		backend.ProcessCacheSize = cfg.Sensor.ProcessCacheSize
		backend.DataCacheSize = cfg.Sensor.DataCacheSize
		backend.EventQueueSize = cfg.Sensor.EventQueueSize
		backend.RBQueueSize = cfg.Sensor.RBQueueSize
		scope, err := cfg.Sensor.EffectiveScope()
		if err != nil {
			return nil, err
		}
		backend.ScopeType = scope.Type
		backend.ScopeSelector = scope.Selector
		backend.BTFPath = cfg.Sensor.BTFPath
		backend.BPFFSPath = cfg.Sensor.BPFFSPath
		backend.RequireBTF = cfg.Sensor.RequireBTF
		backend.RequireBPFFS = cfg.Sensor.RequireBPFFS
		return backend, nil
	default:
		return nil, fmt.Errorf("unsupported sensor backend %q", cfg.Sensor.Backend)
	}
}

func tetragonRestartPolicy(cfg config.SensorConfig) (tetragon.ProcessRestartPolicy, error) {
	switch cfg.Restart {
	case "", "never", "off", "false":
		return tetragon.ProcessRestartPolicy{}, nil
	case "always":
		return tetragon.ProcessRestartPolicy{
			Enabled:     true,
			MaxRestarts: cfg.MaxRestarts,
			Delay:       cfg.RestartWindow,
		}, nil
	default:
		return tetragon.ProcessRestartPolicy{}, fmt.Errorf("unsupported sensor.restart %q", cfg.Restart)
	}
}
