package policy

import (
	"encoding/json"
	"time"
)

type policyWire struct {
	PolicyID      string             `json:"policy_id"`
	Version       uint64             `json:"version"`
	TenantID      string             `json:"tenant_id"`
	Scope         scopeWire          `json:"scope,omitempty"`
	Detection     *detectionWire     `json:"detection,omitempty"`
	Telemetry     *telemetryWire     `json:"telemetry,omitempty"`
	Collection    *collectionWire    `json:"collection,omitempty"`
	EndpointRules []string           `json:"endpoint_rules,omitempty"`
	CloudRules    []string           `json:"cloud_rules,omitempty"`
	Mode          string             `json:"mode,omitempty"`
	Converge      *convergeWire      `json:"converge,omitempty"`
	Rarity        *rarityWire        `json:"rarity,omitempty"`
	Response      responsePolicyWire `json:"response_policy,omitempty"`
	Published     bool               `json:"published"`
	CreatedAt     time.Time          `json:"created_at,omitempty"`
	UpdatedAt     time.Time          `json:"updated_at,omitempty"`
}

type endpointPolicyWire struct {
	PolicyID   string              `json:"policy_id"`
	Version    uint64              `json:"version"`
	Collection json.RawMessage     `json:"collection"`
	Detection  *detectionWire      `json:"detection"`
	Telemetry  *telemetryWire      `json:"telemetry"`
	Response   *responsePolicyWire `json:"response"`
}

type detectionWire struct {
	PolicyID      string             `json:"policy_id,omitempty"`
	Version       uint64             `json:"version,omitempty"`
	Mode          string             `json:"mode,omitempty"`
	Scope         scopeWire          `json:"scope,omitempty"`
	RuleSets      []ruleSetWire      `json:"rulesets,omitempty"`
	RuleOverrides []ruleOverrideWire `json:"rule_overrides,omitempty"`
	ContextRefs   []contentRefWire   `json:"context_refs,omitempty"`
	IOCRefs       []contentRefWire   `json:"ioc_refs,omitempty"`
	LearningModel *learningModelWire `json:"learning_model,omitempty"`
}

type learningModelWire struct {
	Ref     string `json:"ref"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type ruleSetWire struct {
	Ref     string   `json:"ref"`
	Version string   `json:"version,omitempty"`
	Enabled *bool    `json:"enabled,omitempty"`
	IOCRefs []string `json:"ioc_refs,omitempty"`
}

type ruleOverrideWire struct {
	RuleID         string              `json:"rule_id"`
	Enabled        *bool               `json:"enabled,omitempty"`
	Mode           string              `json:"mode,omitempty"`
	Severity       string              `json:"severity,omitempty"`
	Scope          scopeWire           `json:"scope,omitempty"`
	ResponseIntent *responseIntentWire `json:"response_intent,omitempty"`
	Params         map[string]string   `json:"params,omitempty"`
	Reason         string              `json:"reason,omitempty"`
}

type responseIntentWire struct {
	Action     string `json:"action,omitempty"`
	Confidence uint32 `json:"confidence,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type contentRefWire struct {
	Ref     string `json:"ref"`
	Version string `json:"version,omitempty"`
}

type telemetryWire struct {
	MaxBatchItems int    `json:"max_batch_items,omitempty"`
	MaxBatchBytes int    `json:"max_batch_bytes,omitempty"`
	FlushInterval string `json:"flush_interval,omitempty"`
}

type scopeWire struct {
	Type     string `json:"type,omitempty"`
	Selector string `json:"selector,omitempty"`
}

type convergeWire struct {
	Mode                  string `json:"mode,omitempty"`
	TopK                  uint32 `json:"top_k,omitempty"`
	MaxPathHops           uint32 `json:"max_path_hops,omitempty"`
	AdditiveRiskThreshold uint32 `json:"additive_risk_threshold,omitempty"`
	CrossLineage          bool   `json:"cross_lineage,omitempty"`
}

type rarityWire struct {
	CMSWidth         uint32 `json:"cms_width,omitempty"`
	CMSDepth         uint32 `json:"cms_depth,omitempty"`
	BaselineWindowNS uint64 `json:"baseline_window_ns,omitempty"`
}

type responsePolicyWire struct {
	AllowedActions    []string `json:"allowed_actions,omitempty"`
	AllowedModes      []string `json:"allowed_modes,omitempty"`
	ApprovalRequired  bool     `json:"approval_required,omitempty"`
	ApprovalThreshold uint32   `json:"approval_threshold,omitempty"`
	ApprovalRoles     []string `json:"approval_roles,omitempty"`
	AllowDestructive  bool     `json:"allow_destructive,omitempty"`
}
