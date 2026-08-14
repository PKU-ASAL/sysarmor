package config

import "time"

type Config struct {
	Agent     AgentConfig
	Local     LocalConfig
	Manager   ManagerConfig
	Control   ControlConfig
	Runtime   RuntimeConfig
	Sensor    SensorConfig
	Telemetry TelemetryConfig
	Health    HealthConfig
	Policy    PolicyConfig
	Content   ContentConfig
	Resource  ResourceConfig
}

type AgentConfig struct {
	ID, HostID, TenantID, Token string
	Labels                      map[string]string
}

type LocalConfig struct {
	StatePath string
	Storage   LocalStorageConfig
	Export    LocalExportConfig
}

type LocalStorageConfig struct {
	MaxBytes, MinFreeBytes, SegmentSize, SignalMaxCount int64
}

type LocalExportConfig struct {
	RetryInitial, RetryMax, RequestTimeout time.Duration
	MaxInflight                            int
	WireCompression                        string
}

type ManagerConfig struct {
	Address, Transport, TLSCA, TLSCert, TLSKey, TLSServerName string
	TLSInsecure                                               bool
}

type ControlConfig struct{ SocketPath string }
type RuntimeConfig struct{ FeatureFlags RuntimeFeatureFlags }
type RuntimeFeatureFlags struct{ MatcherStrategy string }

type SensorConfig struct {
	Backend, Mode, Version, BundleDir, InstallDir          string
	TetraPath, TetragonPath, EventTransport, ServerAddress string
	CgroupRate, PprofAddress, GopsAddress                  string
	ProcessCacheSize, DataCacheSize, EventQueueSize        int
	RBQueueSize, BTFPath, BPFFSPath                        string
	RequireBTF, RequireBPFFS                               bool
	PolicyPath, EventSource                                string
	Scope                                                  RuntimeScope
	FakeStartupEvents                                      int
	ObserveOnly                                            bool
	Restart                                                string
	MaxRestarts                                            int
	MaxParseErrors, MaxDroppedEvents                       uint64
	RestartWindow                                          time.Duration
}

type RuntimeScope struct{ Type, Selector string }

type TelemetryConfig struct {
	MaxBatchItems, MaxBatchBytes int
	FlushInterval                time.Duration
}

type HealthConfig struct{ Interval time.Duration }
type PolicyConfig struct{ Path string }
type ContentConfig struct{ DefaultPath, Path, TrustKeys string }
type ResourceConfig struct{ MaxActiveCEPGroups, MaxEventRefsPerSignal int }
