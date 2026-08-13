package control

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
	Status          string
	Message         string
	RequiresRestart bool
	Details         []string
	ReportJSON      string
}

type Result struct {
	RequestID       string
	TenantID        string
	AgentID         string
	Status          string
	Message         string
	PolicyID        string
	Version         uint64
	RequiresRestart bool
	Sections        []SectionResult
	Details         []string
	ReportJSON      string
}
