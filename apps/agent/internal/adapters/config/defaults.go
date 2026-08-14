package config

import "time"

func defaults() Config {
	return Config{
		Local: LocalConfig{
			StatePath: "/var/lib/sysarmor/agent",
			Storage:   LocalStorageConfig{MaxBytes: 10 << 30, MinFreeBytes: 2 << 30, SegmentSize: 64 << 20, SignalMaxCount: 100_000},
			Export:    LocalExportConfig{RetryInitial: time.Second, RetryMax: 30 * time.Second, RequestTimeout: 10 * time.Second, MaxInflight: 1, WireCompression: "none"},
		},
		Control:   ControlConfig{SocketPath: "/run/sysarmor/agent/control.sock"},
		Runtime:   RuntimeConfig{FeatureFlags: RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:    SensorConfig{Backend: "tetragon", Mode: "managed", EventTransport: "grpc", ServerAddress: "unix:///var/run/tetragon/tetragon.sock", ProcessCacheSize: 4096, DataCacheSize: 128, EventQueueSize: 1024, RBQueueSize: "8192", ObserveOnly: true, Restart: "always", MaxRestarts: 5, RestartWindow: time.Minute},
		Telemetry: DefaultTelemetryConfig(), Health: HealthConfig{Interval: 10 * time.Second},
		Policy: PolicyConfig{Path: "/etc/sysarmor/agent/policy.json"}, Content: ContentConfig{Path: "/var/lib/sysarmor/agent/content"},
		Resource: ResourceConfig{MaxActiveCEPGroups: 4096, MaxEventRefsPerSignal: 128},
	}
}
