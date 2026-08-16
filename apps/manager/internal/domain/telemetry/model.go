package telemetry

type Document []byte

type Index string

const (
	IndexEvents  Index = "events"
	IndexSignals Index = "signals"
)

type IndexedDocument struct {
	Index    Index
	Document Document
}

type IncidentOverview struct {
	Open     int
	Critical int
	High     int
	Medium   int
}

type Entity struct {
	Kind string
	Key  string
	Role string
}

type Event struct {
	ID             string
	Sequence       uint64
	AgentID        string
	HostID         string
	MonotonicNS    uint64
	SubjectProcess *ProcessRef
	Object         *ObjectRef
	ParentStableID string
	LineageID      string
	RawRef         string
	TenantID       string
	Scope          *RuntimeScope
	ContainerID    string
	Cgroup         string
	Namespace      string
	Pod            string
	OccurredAtNS   uint64
	Behavior       string
	Labels         map[string]string
}

type ProcessRef struct {
	StableID              string
	PID                   uint32
	Binary                string
	Argv                  []string
	UID                   uint32
	StartTimeNS           uint64
	ArgvBoundariesTrusted bool
}

type ObjectRef struct {
	Kind               string
	FilePath           string
	SocketAddress      string
	TargetProcStableID string
}

type RuntimeScope struct {
	Type     string
	Selector string
}

type SignalWhere int32
type SignalStage int32
type DetectorKind int32

const (
	SignalWhereUnspecified SignalWhere = 0
	SignalWhereEndpoint    SignalWhere = 1
	SignalWhereCloud       SignalWhere = 2
)

const (
	SignalStageUnspecified SignalStage = iota
	SignalStageCandidate
	SignalStageConclusion
)

const (
	DetectorKindUnspecified DetectorKind = iota
	DetectorKindRule
	DetectorKindModel
	DetectorKindGraph
	DetectorKindSystem
)

type Signal struct {
	ID           string
	Name         string
	Where        SignalWhere
	BaseRisk     uint32
	LocalRarity  float32
	GlobalRarity float32
	Entities     []Entity
	Labels       map[string]string
	LineageID    string
	Stage        SignalStage
	DetectorKind DetectorKind
	CrossLineage bool
	EventRefs    []string
	SignalRefs   []string
	Evidence     *EvidenceBundle
	Response     *ResponseIntent
	RuleID       string
	RuleVersion  uint64
	RulesetRef   string
	ContextRefs  []ContentRef
	IOCRefs      []ContentRef
	Severity     string
	Confidence   uint32
	Mode         string
}

type EvidenceBundle struct {
	ID        string
	EventRefs []string
	RawRefs   []string
	Entities  []Entity
	Summary   string
}

type ResponseIntent struct {
	Intent            string
	RecommendedAction string
	Confidence        uint32
	Reason            string
}

type ContentRef struct {
	Ref     string
	Version string
	Digest  string
}

type GraphNode struct {
	ID       string
	Kind     string
	Label    string
	Entities []Entity
}

type GraphEdge struct {
	ID   string
	From string
	To   string
	Kind string
}

type EvidenceSubgraph struct {
	Nodes []GraphNode
	Edges []GraphEdge
}

type ConvergeTrace struct {
	Method   string
	SeedIDs  []string
	PathIDs  []string
	Score    float32
	Controls []string
}

type Incident struct {
	ID                  string
	Summary             string
	Severity            uint32
	MITRE               []string
	LineageIDs          []string
	ConclusionEntities  []string
	Evidence            *EvidenceSubgraph
	Converge            *ConvergeTrace
	ContributingSignals []Signal
	Labels              map[string]string
	TenantID            string
	CorrelationKey      string
	AnalysisVersion     string
	FirstObservedAt     string
	LastObservedAt      string
}

type Analysis struct {
	CloudSignals []Signal
	Incidents    []Incident
}

func (document Document) Clone() Document {
	return append(Document(nil), document...)
}
