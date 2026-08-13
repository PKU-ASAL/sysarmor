package detection

type SignalWhere uint8

const (
	SignalWhereUnspecified SignalWhere = iota
	SignalWhereEndpoint
	SignalWhereCloud
)

type Entity struct {
	Kind string
	Key  string
	Role string
}

type Evidence struct {
	ID        string
	EventRefs []string
	RawRefs   []string
	Entities  []Entity
	Summary   string
}

type ContentRef struct {
	Ref     string
	Version string
	Digest  string
}

type Signal struct {
	ID             string
	Name           string
	Where          SignalWhere
	BaseRisk       uint32
	LocalRarity    float32
	GlobalRarity   float32
	LineageID      string
	Entities       []Entity
	EventRefs      []string
	SignalRefs     []string
	Terminal       bool
	Evidence       *Evidence
	CrossLineage   bool
	ResponseIntent *ResponseIntent
	RuleID         string
	RuleVersion    uint64
	RuleSetRef     string
	ContextRefs    []ContentRef
	IOCRefs        []ContentRef
	Severity       string
	Confidence     uint32
	Mode           string
	Labels         map[string]string
}
