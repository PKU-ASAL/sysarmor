package policy

import domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"

const (
	DefaultPolicyID       = "default-edr-policy"
	DefaultPolicyVersion  = uint64(1)
	DefaultRuleSetRef     = "ruleset:cep-endpoint"
	DefaultRuleSetVersion = "v1"
)

func DefaultPolicy(tenantID string) Policy {
	if tenantID == "" {
		tenantID = "default"
	}
	return Policy{
		PolicyID: DefaultPolicyID, Version: DefaultPolicyVersion, TenantID: tenantID,
		Detection:  DefaultDetectionPolicy(),
		CloudRules: []string{"dropped_payload_executed_and_connects", "web_shell_chain"},
		Mode:       "observe", Converge: defaultConvergeParams(),
		Response: defaultResponsePolicy(), Published: true,
	}
}

func DefaultManagedPolicy(tenantID string) Policy {
	value := DefaultPolicy(tenantID)
	enabled := true
	value.Detection.RuleSets = []RuleSetRef{{
		Ref: DefaultRuleSetRef, Version: DefaultRuleSetVersion, Enabled: &enabled,
	}}
	return value
}

func DefaultDetectionPolicy() *DetectionPolicy {
	return &DetectionPolicy{
		PolicyID: "default-endpoint-detection", Version: 1, Mode: "observe",
	}
}

func defaultConvergeParams() *ConvergeParams {
	return &ConvergeParams{
		Mode: "rarity_structural", CrossLineage: true, TopK: 8, MaxPathHops: 6,
	}
}

func defaultResponsePolicy() domainresponse.Policy {
	return domainresponse.DefaultPolicy()
}
