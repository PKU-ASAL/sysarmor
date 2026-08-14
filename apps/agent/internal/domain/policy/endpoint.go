package policy

import (
	"time"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
)

type Policy struct {
	PolicyID      string
	Version       uint64
	TenantID      string
	Scope         ScopeSelector
	Detection     *DetectionPolicy
	Telemetry     *TelemetryPolicy
	Collection    *CollectionPolicy
	EndpointRules []string
	CloudRules    []string
	Mode          string
	Converge      *ConvergeParams
	Rarity        *RarityParams
	Response      domainresponse.Policy
	Published     bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type EndpointPolicy struct {
	PolicyID   string
	Version    uint64
	Collection CollectionPolicy
	Detection  DetectionPolicy
	Telemetry  TelemetryPolicy
	Response   domainresponse.Policy
}

type DetectionPolicy struct {
	PolicyID      string
	Version       uint64
	Mode          string
	Scope         ScopeSelector
	RuleSets      []RuleSetRef
	RuleOverrides []RuleOverride
	ContextRefs   []ContentRef
	IOCRefs       []ContentRef
}

type RuleSetRef struct {
	Ref     string
	Version string
	Enabled *bool
	IOCRefs []string
}

type RuleOverride struct {
	RuleID         string
	Enabled        *bool
	Mode           string
	Severity       string
	Scope          ScopeSelector
	ResponseIntent *ResponseIntentRef
	Params         map[string]string
	Reason         string
}

type ResponseIntentRef struct {
	Action     string
	Confidence uint32
	Reason     string
}

type ContentRef struct {
	Ref     string
	Version string
}

type TelemetryPolicy struct {
	MaxBatchItems int
	MaxBatchBytes int
	FlushInterval string
}

type ScopeSelector struct {
	Type     string
	Selector string
}

type ConvergeParams struct {
	Mode                  string
	TopK                  uint32
	MaxPathHops           uint32
	AdditiveRiskThreshold uint32
	CrossLineage          bool
}

type RarityParams struct {
	CMSWidth         uint32
	CMSDepth         uint32
	BaselineWindowNS uint64
}
