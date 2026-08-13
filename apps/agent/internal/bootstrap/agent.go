package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/daemon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/fake"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Agent struct {
	runtime *daemon.AgentRuntime
	store   *localstore.Store
}

type ConfigSummary struct {
	AgentID       string
	HostID        string
	TenantID      string
	Manager       string
	SensorBackend string
	SensorMode    string
}

func ValidateConfig(path string) (ConfigSummary, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return ConfigSummary{}, err
	}
	return ConfigSummary{
		AgentID: cfg.Agent.ID, HostID: cfg.Agent.HostID, TenantID: cfg.Agent.TenantID,
		Manager: cfg.Manager.Address, SensorBackend: cfg.Sensor.Backend, SensorMode: cfg.Sensor.Mode,
	}, nil
}

func NewAgentFromFile(ctx context.Context, path string) (*Agent, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return NewAgent(ctx, cfg)
}

func NewAgent(ctx context.Context, cfg config.Config) (*Agent, error) {
	featureFlags, err := applyRuntimeFeatureFlags(cfg)
	if err != nil {
		return nil, err
	}
	sensor, err := sensorFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	contentStore, err := contentStoreFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("load startup content: %w", err)
	}
	dependencies := daemon.Dependencies{Config: cfg, Sensor: sensor, Content: contentStore, FeatureFlags: featureFlags}
	store, err := configureLocalState(ctx, &dependencies)
	if err != nil {
		return nil, err
	}
	return &Agent{runtime: daemon.NewRuntime(dependencies), store: store}, nil
}

func (agent *Agent) Run(ctx context.Context, out io.Writer) error {
	return agent.runtime.Run(ctx, daemon.Options{Out: out})
}

func (agent *Agent) Close() error {
	if agent == nil || agent.store == nil {
		return nil
	}
	return agent.store.Close()
}

func configureLocalState(ctx context.Context, dependencies *daemon.Dependencies) (*localstore.Store, error) {
	if dependencies.Config.Manager.Transport != "" {
		return nil, nil
	}
	cfg := &dependencies.Config
	store, err := localstore.Open(ctx, localstore.Options{
		RootDir: cfg.Local.StatePath, MaxBytes: cfg.Local.Storage.MaxBytes,
		MinFreeBytes: cfg.Local.Storage.MinFreeBytes, SegmentSize: cfg.Local.Storage.SegmentSize,
		SignalMaxCount: cfg.Local.Storage.SignalMaxCount,
	})
	if err != nil {
		return nil, fmt.Errorf("open agent local store: %w", err)
	}
	if err := loadLocalState(ctx, dependencies, store); err != nil {
		_ = store.Close()
		return nil, err
	}
	dependencies.LocalStore = store
	return store, nil
}

func loadLocalState(ctx context.Context, dependencies *daemon.Dependencies, store *localstore.Store) error {
	identity, err := store.DeviceIdentity(ctx)
	if err != nil {
		return fmt.Errorf("load device identity: %w", err)
	}
	if dependencies.Config.Agent.ID == "" {
		dependencies.Config.Agent.ID = identity.DeviceID
	}
	if dependencies.Config.Agent.HostID == "" {
		dependencies.Config.Agent.HostID = identity.HostID
	}
	if dependencies.Config.Agent.TenantID == "" {
		dependencies.Config.Agent.TenantID = "local"
	}
	cursor, err := store.SequenceCursor(ctx)
	if err != nil {
		return fmt.Errorf("load local sequence cursor: %w", err)
	}
	dependencies.EventSeq, dependencies.SignalSeq = cursor.Event, cursor.Signal
	return nil
}

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

func contentStoreFromConfig(cfg config.Config) (*agentcontent.Store, error) {
	options := agentcontent.Options{DefaultDir: cfg.Content.DefaultPath, Dir: cfg.Content.Path, TrustedKeys: parseTrustKeys(cfg.Content.TrustKeys)}
	if strings.TrimSpace(options.DefaultDir) != "" {
		return agentcontent.OpenLayered(options)
	}
	return agentcontent.NewStoreWithOptions(options)
}

func parseTrustKeys(raw string) map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	for _, item := range strings.Split(raw, ",") {
		keyID, encoded, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || strings.TrimSpace(keyID) == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err == nil && len(data) == ed25519.PublicKeySize {
			keys[strings.TrimSpace(keyID)] = ed25519.PublicKey(data)
		}
	}
	return keys
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
		return tetragonSensor(cfg)
	default:
		return nil, fmt.Errorf("unsupported sensor backend %q", cfg.Sensor.Backend)
	}
}

func tetragonSensor(cfg config.Config) (contract.Sensor, error) {
	restart, err := tetragonRestartPolicy(cfg.Sensor)
	if err != nil {
		return nil, err
	}
	scope, err := cfg.Sensor.EffectiveScope()
	if err != nil {
		return nil, err
	}
	backend := tetragon.NewBackendWithOptions(cfg.Sensor.PolicyPath, cfg.Sensor.EventSource, cfg.Sensor.Version, tetragon.BundleConfig{
		BundleDir: cfg.Sensor.BundleDir, InstallDir: cfg.Sensor.InstallDir,
		TetraPath: cfg.Sensor.TetraPath, TetragonPath: cfg.Sensor.TetragonPath,
	}, restart)
	applyTetragonConfig(backend, cfg.Sensor, scope)
	return backend, nil
}

func applyTetragonConfig(backend *tetragon.Backend, cfg config.SensorConfig, scope config.RuntimeScope) {
	backend.EventTransport, backend.ServerAddress = cfg.EventTransport, cfg.ServerAddress
	backend.CgroupRate, backend.PprofAddress, backend.GopsAddress = cfg.CgroupRate, cfg.PprofAddress, cfg.GopsAddress
	backend.ProcessCacheSize, backend.DataCacheSize, backend.EventQueueSize = cfg.ProcessCacheSize, cfg.DataCacheSize, cfg.EventQueueSize
	backend.RBQueueSize, backend.BTFPath, backend.BPFFSPath = cfg.RBQueueSize, cfg.BTFPath, cfg.BPFFSPath
	backend.RequireBTF, backend.RequireBPFFS = cfg.RequireBTF, cfg.RequireBPFFS
	backend.ScopeType, backend.ScopeSelector = scope.Type, scope.Selector
}

func tetragonRestartPolicy(cfg config.SensorConfig) (tetragon.ProcessRestartPolicy, error) {
	switch cfg.Restart {
	case "", "never", "off", "false":
		return tetragon.ProcessRestartPolicy{}, nil
	case "always":
		return tetragon.ProcessRestartPolicy{Enabled: true, MaxRestarts: cfg.MaxRestarts, Delay: cfg.RestartWindow}, nil
	default:
		return tetragon.ProcessRestartPolicy{}, fmt.Errorf("unsupported sensor.restart %q", cfg.Restart)
	}
}
