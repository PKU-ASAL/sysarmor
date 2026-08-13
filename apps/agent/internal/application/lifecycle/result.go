package lifecycle

type Status string

const (
	StatusApplied  Status = "applied"
	StatusPending  Status = "pending"
	StatusRejected Status = "rejected"
)

type Identity struct {
	TenantID string
	AgentID  string
}

type Scope struct {
	Type     string
	Selector string
}

type RequestContext struct {
	RequestID string
	TenantID  string
	AgentID   string
	Scope     *Scope
}

type SectionResult struct {
	Name            string
	Status          Status
	Message         string
	RequiresRestart bool
	Details         []string
	ReportJSON      string
}

type Result struct {
	RequestID       string
	TenantID        string
	AgentID         string
	Status          Status
	Message         string
	PolicyID        string
	Version         uint64
	RequiresRestart bool
	Sections        []SectionResult
	Details         []string
	ReportJSON      string
}
