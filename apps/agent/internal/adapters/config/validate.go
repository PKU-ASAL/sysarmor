package config

import (
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (c Config) Validate() error {
	var missing []string
	checks := []struct{ path, value string }{
		{"local.state_path", c.Local.StatePath}, {"sensor.backend", c.Sensor.Backend},
		{"sensor.mode", c.Sensor.Mode}, {"policy.path", c.Policy.Path},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.value) == "" {
			missing = append(missing, check.path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	if !validMatcherStrategy(c.Runtime.FeatureFlags.MatcherStrategy) {
		return fmt.Errorf("runtime.feature_flags.matcher_strategy must be linear or optimized")
	}
	if (c.Manager.TLSCert == "") != (c.Manager.TLSKey == "") {
		return fmt.Errorf("manager.tls_cert and manager.tls_key must be configured together")
	}
	if c.Sensor.Backend != "tetragon" && c.Sensor.Backend != "fake" {
		return fmt.Errorf("sensor.backend must be tetragon or fake")
	}
	if c.Sensor.Mode != "managed" && c.Sensor.Mode != "external" {
		return fmt.Errorf("sensor.mode must be managed or external")
	}
	if c.Sensor.EventTransport == "" {
		c.Sensor.EventTransport = "grpc"
	}
	if c.Sensor.EventTransport != "grpc" && c.Sensor.EventTransport != "tetra" {
		return fmt.Errorf("sensor.event_transport must be grpc or tetra")
	}
	if err := validateSensorNumbers(c.Sensor); err != nil {
		return err
	}
	scope, err := c.Sensor.EffectiveScope()
	if err != nil {
		return fmt.Errorf("sensor scope: %w", err)
	}
	if scope.Type == "namespace" && scope.Selector != "self" {
		return fmt.Errorf("sensor scope: namespace scope selector must be self")
	}
	if _, err := ResolveTelemetry(c.Telemetry, nil); err != nil {
		return err
	}
	return validateRuntimeLimits(c)
}

func validateSensorNumbers(sensor SensorConfig) error {
	for path, value := range map[string]int{"process_cache_size": sensor.ProcessCacheSize, "data_cache_size": sensor.DataCacheSize, "event_queue_size": sensor.EventQueueSize, "max_restarts": sensor.MaxRestarts, "fake_startup_events": sensor.FakeStartupEvents} {
		if value < 0 {
			return fmt.Errorf("sensor.%s must be non-negative", path)
		}
	}
	return nil
}

func validateRuntimeLimits(c Config) error {
	if c.Local.Export.RetryInitial <= 0 || c.Local.Export.RetryMax <= 0 || c.Local.Export.RequestTimeout <= 0 {
		return fmt.Errorf("local.export retry/request timeouts must be positive")
	}
	if c.Local.Export.RetryInitial > c.Local.Export.RetryMax {
		return fmt.Errorf("local.export.retry_initial must be <= local.export.retry_max")
	}
	if c.Local.Export.MaxInflight != 1 {
		return fmt.Errorf("local.export.max_inflight must be 1")
	}
	if c.Local.Storage.MaxBytes <= 0 || c.Local.Storage.MinFreeBytes <= 0 || c.Local.Storage.SegmentSize <= 0 || c.Local.Storage.SignalMaxCount <= 0 {
		return fmt.Errorf("local.storage limits must be positive")
	}
	if c.Health.Interval <= 0 {
		return fmt.Errorf("health.interval must be positive")
	}
	if c.Resource.MaxActiveCEPGroups < 0 {
		return fmt.Errorf("resource.max_active_cep_groups must be non-negative")
	}
	if c.Resource.MaxEventRefsPerSignal < 0 {
		return fmt.Errorf("resource.max_event_refs_per_signal must be non-negative")
	}
	return nil
}

func (s SensorConfig) EffectiveScope() (RuntimeScope, error) {
	scopeType, selector, err := contract.NormalizeScope(s.Scope.Type, s.Scope.Selector)
	if err != nil {
		return RuntimeScope{}, err
	}
	return RuntimeScope{Type: scopeType, Selector: selector}, nil
}

func validMatcherStrategy(strategy string) bool {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "", "linear", "optimized":
		return true
	default:
		return false
	}
}
