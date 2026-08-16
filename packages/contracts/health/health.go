package health

import "time"

type AgentHealth struct {
	AgentID          string                 `json:"agent_id"`
	HostID           string                 `json:"host_id"`
	TenantID         string                 `json:"tenant_id"`
	Scope            RuntimeScope           `json:"scope"`
	Status           string                 `json:"status"`
	PolicyID         string                 `json:"policy_id,omitempty"`
	PolicyVersion    uint64                 `json:"policy_version,omitempty"`
	PolicyMode       string                 `json:"policy_mode,omitempty"`
	PendingPolicy    PendingPolicyStatus    `json:"pending_policy,omitempty"`
	UptimeSeconds    int64                  `json:"uptime_seconds"`
	Capability       SensorCapability       `json:"sensor_capability,omitempty"`
	Sensor           SensorHealth           `json:"sensor_health"`
	TelemetryBus     TelemetryBusHealth     `json:"telemetry_bus_health"`
	TelemetryBatcher TelemetryBatcherHealth `json:"telemetry_batcher_health"`
	TelemetrySender  TelemetrySenderHealth  `json:"telemetry_sender_health"`
	Detection        DetectionHealth        `json:"detection_health"`
	CEP              CEPHealth              `json:"cep_health"`
	Streams          LocalStreamHealth      `json:"stream_health"`
	ObservedAt       time.Time              `json:"observed_at"`
}

type PendingPolicyStatus struct {
	Status   string `json:"status,omitempty"`
	Source   string `json:"source,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	Version  uint64 `json:"version,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

type DetectionHealth struct {
	PolicyID               string              `json:"policy_id,omitempty"`
	PolicyVersion          uint64              `json:"policy_version,omitempty"`
	ContentRefs            []ContentRef        `json:"content_refs,omitempty"`
	DefaultManifestVersion string              `json:"default_manifest_version,omitempty"`
	FeatureFlags           RuntimeFeatureFlags `json:"feature_flags,omitempty"`
	LastApplyStatus        string              `json:"last_apply_status,omitempty"`
	LastApplyError         string              `json:"last_apply_error,omitempty"`
	UpdatedAt              time.Time           `json:"updated_at,omitempty"`
	Learning               LearningHealth      `json:"learning,omitempty"`
}

type LearningHealth struct {
	Status    string `json:"status,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type ContentRef struct {
	Ref     string `json:"ref"`
	Kind    string `json:"kind,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

type RuntimeFeatureFlags struct {
	MatcherStrategy string `json:"matcher_strategy,omitempty"`
}

type RuntimeScope struct {
	Type     string `json:"type"`
	Selector string `json:"selector,omitempty"`
}

type SensorHealth struct {
	Backend        string    `json:"backend"`
	Installed      bool      `json:"installed"`
	Running        bool      `json:"running"`
	Version        string    `json:"version"`
	PolicyLoaded   bool      `json:"policy_loaded"`
	EventsSeen     uint64    `json:"events_seen"`
	EventsDropped  uint64    `json:"events_dropped"`
	ParseErrors    uint64    `json:"parse_errors"`
	RestartCount   uint64    `json:"restart_count"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
	LastExitReason string    `json:"last_exit_reason,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

type SensorCapability struct {
	Backend         string                         `json:"backend,omitempty"`
	Version         string                         `json:"version,omitempty"`
	SupportsExec    bool                           `json:"supports_exec,omitempty"`
	SupportsConnect bool                           `json:"supports_connect,omitempty"`
	SupportsFile    bool                           `json:"supports_file,omitempty"`
	SupportsEnforce bool                           `json:"supports_enforce,omitempty"`
	SupportsHealth  bool                           `json:"supports_health,omitempty"`
	KernelRelease   string                         `json:"kernel_release,omitempty"`
	BTFAvailable    bool                           `json:"btf_available,omitempty"`
	BPFFSAvailable  bool                           `json:"bpffs_available,omitempty"`
	Collection      []CollectionBehaviorCapability `json:"collection,omitempty"`
}

type CollectionBehaviorCapability struct {
	Behavior             string   `json:"behavior"`
	SensorMapping        string   `json:"sensor_mapping,omitempty"`
	Fields               []string `json:"fields"`
	PushdownSelectors    []string `json:"pushdown_selectors,omitempty"`
	AgentSideSelectors   []string `json:"agent_side_selectors,omitempty"`
	UnsupportedSelectors []string `json:"unsupported_selectors,omitempty"`
}

type TelemetryBusHealth struct {
	EventCapacity     uint64 `json:"event_capacity"`
	EventBuffered     uint64 `json:"event_buffered"`
	EventSubscribers  uint64 `json:"event_subscribers"`
	SignalCapacity    uint64 `json:"signal_capacity"`
	SignalBuffered    uint64 `json:"signal_buffered"`
	SignalSubscribers uint64 `json:"signal_subscribers"`
}

type TelemetryBatcherHealth struct {
	PendingEvents     uint64 `json:"pending_events"`
	PendingSignals    uint64 `json:"pending_signals"`
	QueuedBatches     uint64 `json:"queued_batches"`
	QueueCapacity     uint64 `json:"queue_capacity"`
	DroppedBatches    uint64 `json:"dropped_batches"`
	DroppedEvents     uint64 `json:"dropped_events"`
	DroppedSignals    uint64 `json:"dropped_signals"`
	FlushedBatches    uint64 `json:"flushed_batches"`
	FlushedEvents     uint64 `json:"flushed_events"`
	FlushedSignals    uint64 `json:"flushed_signals"`
	PendingBytes      uint64 `json:"pending_bytes"`
	MaxBytes          uint64 `json:"max_bytes"`
	FlushedByCount    uint64 `json:"flushed_by_count"`
	FlushedByBytes    uint64 `json:"flushed_by_bytes"`
	FlushedByInterval uint64 `json:"flushed_by_interval"`
	FlushedByShutdown uint64 `json:"flushed_by_shutdown"`
	LastFlushReason   string `json:"last_flush_reason,omitempty"`
	Closed            bool   `json:"closed"`
	LastError         string `json:"last_error,omitempty"`
}

type TelemetrySenderHealth struct {
	SentBatches     uint64 `json:"sent_batches"`
	SentEvents      uint64 `json:"sent_events"`
	SentSignals     uint64 `json:"sent_signals"`
	RejectedBatches uint64 `json:"rejected_batches"`
	RetriedBatches  uint64 `json:"retried_batches"`
	Drained         bool   `json:"drained"`
	LastError       string `json:"last_error,omitempty"`
}

type CEPHealth struct {
	ActiveGroups     uint64 `json:"active_groups"`
	EvictedGroups    uint64 `json:"evicted_groups"`
	ExpiredGroups    uint64 `json:"expired_groups"`
	DroppedEventRefs uint64 `json:"dropped_event_refs"`
	EvalErrors       uint64 `json:"eval_errors"`
	EmittedSignals   uint64 `json:"emitted_signals"`
	Degraded         bool   `json:"degraded"`
}

type LocalStreamHealth struct {
	EventCapacity        uint64 `json:"event_capacity"`
	EventBuffered        uint64 `json:"event_buffered"`
	EventNextSequence    uint64 `json:"event_next_sequence"`
	EventOldestSequence  uint64 `json:"event_oldest_sequence"`
	EventNewestSequence  uint64 `json:"event_newest_sequence"`
	EventEvicted         uint64 `json:"event_evicted"`
	EventSubscribers     uint64 `json:"event_subscribers"`
	SignalCapacity       uint64 `json:"signal_capacity"`
	SignalBuffered       uint64 `json:"signal_buffered"`
	SignalNextSequence   uint64 `json:"signal_next_sequence"`
	SignalOldestSequence uint64 `json:"signal_oldest_sequence"`
	SignalNewestSequence uint64 `json:"signal_newest_sequence"`
	SignalEvicted        uint64 `json:"signal_evicted"`
	SignalSubscribers    uint64 `json:"signal_subscribers"`
}
