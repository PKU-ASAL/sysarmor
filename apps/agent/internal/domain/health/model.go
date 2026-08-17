package health

import "time"

type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
)

type Runtime struct {
	AgentID       string
	HostID        string
	TenantID      string
	ScopeType     string
	ScopeSelector string
	PolicyID      string
	PolicyVersion uint64
	PolicyMode    string
	StartedAt     time.Time
	PendingPolicy PendingPolicy
	Capability    Capability
	LastError     string
}

type PendingPolicy struct {
	Status, Source, PolicyID, Digest string
	Version                          uint64
}

type Capability struct {
	Backend, Version, KernelRelease string
	SupportsExec, SupportsConnect   bool
	SupportsFile, SupportsEnforce   bool
	SupportsHealth                  bool
	BTFAvailable, BPFFSAvailable    bool
	Collection                      []CollectionCapability
}

type CollectionCapability struct {
	Behavior, SensorMapping string
	Fields                  []string
	PushdownSelectors       []string
	AgentSideSelectors      []string
	UnsupportedSelectors    []string
}

type Sensor struct {
	Backend          string
	Installed        bool
	Running          bool
	PolicyLoaded     bool
	Version          string
	EventsSeen       uint64
	EventsDropped    uint64
	ParseErrors      uint64
	MaxDroppedEvents uint64
	MaxParseErrors   uint64
	RestartCount     uint64
	LastEventAt      time.Time
	LastExitReason   string
	LastError        string
}

type Telemetry struct {
	Bus            Bus
	Batcher        Batcher
	Sender         Sender
	Streams        Streams
	DroppedBatches uint64
	DroppedEvents  uint64
	DroppedSignals uint64
	LastError      string
}

type Bus struct {
	EventCapacity, EventBuffered, EventSubscribers    uint64
	SignalCapacity, SignalBuffered, SignalSubscribers uint64
}

type Batcher struct {
	PendingEvents, PendingSignals, QueuedBatches, QueueCapacity uint64
	DroppedBatches, DroppedEvents, DroppedSignals               uint64
	FlushedBatches, FlushedEvents, FlushedSignals               uint64
	PendingBytes, MaxBytes                                      uint64
	FlushedByCount, FlushedByBytes, FlushedByInterval           uint64
	FlushedByShutdown                                           uint64
	LastFlushReason                                             string
	Closed                                                      bool
	LastError                                                   string
}

type Sender struct {
	SentBatches, SentEvents, SentSignals uint64
	RejectedBatches, RetriedBatches      uint64
	Drained                              bool
	LastError                            string
}

type Streams struct {
	EventCapacity, EventBuffered, EventNextSequence, EventOldestSequence uint64
	EventNewestSequence, EventEvicted, EventSubscribers                  uint64
	SignalCapacity, SignalBuffered, SignalNextSequence                   uint64
	SignalOldestSequence, SignalNewestSequence, SignalEvicted            uint64
	SignalSubscribers                                                    uint64
}

type Detection struct {
	PolicyID               string
	PolicyVersion          uint64
	ContentRefs            []ContentRef
	DefaultManifestVersion string
	MatcherStrategy        string
	LastApplyStatus        string
	LastApplyError         string
	UpdatedAt              time.Time
	CEP                    CEP
	PendingPolicy          bool
	EvictedGroups          uint64
	DroppedEventRefs       uint64
	EvalErrors             uint64
	LastError              string
	Learning               Learning
}

type Learning struct {
	Status, LastError string
	Profiles          ProcessProfileHealth
}

type ProcessProfileHealth struct {
	Active, Exited, Retained                           uint64
	Compactions, Expired, CapacityEvictions            uint64
	FileEvictions, NetworkEvictions, EventRefEvictions uint64
}

type ContentRef struct{ Ref, Kind, Version, Digest string }

type CEP struct {
	ActiveGroups, EvictedGroups, ExpiredGroups   uint64
	DroppedEventRefs, EvalErrors, EmittedSignals uint64
	Degraded                                     bool
}

type Storage struct {
	Available                                         bool
	DroppedEvents                                     uint64
	LastError                                         string
	Mode, DeviceID                                    string
	StorageBytes, StorageMaxBytes                     uint64
	OldestEventSequence, LatestEventSequence          uint64
	SignalCount, SealedSegmentCount, OpenSegmentBytes uint64
	UploadSegmentID, DroppedBatches                   uint64
	UploadRecordOffset                                int64
}

type Lifecycle struct {
	Mode                                     string
	TransitionPending                        bool
	LastError                                string
	TransitionPhase, ManagerCompletionStatus string
	RevocationConfirmed                      bool
	UpdatedAt                                time.Time
}

type Snapshot struct {
	Runtime
	Status        Status
	UptimeSeconds int64
	ObservedAt    time.Time
	Sensor        Sensor
	Telemetry     Telemetry
	Detection     Detection
	Storage       Storage
	Lifecycle     Lifecycle
}

func Evaluate(snapshot Snapshot) Status {
	if snapshot.Runtime.LastError != "" || !snapshot.Sensor.Running || snapshot.Sensor.LastError != "" || snapshot.Telemetry.LastError != "" ||
		snapshot.Detection.LastError != "" || snapshot.Detection.Learning.LastError != "" || snapshot.Detection.LastApplyError != "" || snapshot.Detection.LastApplyStatus == "rejected" ||
		snapshot.Storage.LastError != "" || snapshot.Lifecycle.LastError != "" {
		return StatusDegraded
	}
	if sensorLossExceeded(snapshot.Sensor) || snapshot.Telemetry.DroppedBatches > 0 ||
		snapshot.Telemetry.DroppedEvents > 0 || snapshot.Telemetry.DroppedSignals > 0 || snapshot.Storage.DroppedEvents > 0 {
		return StatusDegraded
	}
	if snapshot.Detection.PendingPolicy || snapshot.Detection.EvictedGroups > 0 ||
		snapshot.Detection.DroppedEventRefs > 0 || snapshot.Detection.EvalErrors > 0 || snapshot.Lifecycle.TransitionPending {
		return StatusDegraded
	}
	return StatusOK
}

func sensorLossExceeded(sensor Sensor) bool {
	return sensor.MaxDroppedEvents > 0 && sensor.EventsDropped > sensor.MaxDroppedEvents ||
		sensor.MaxParseErrors > 0 && sensor.ParseErrors > sensor.MaxParseErrors
}
