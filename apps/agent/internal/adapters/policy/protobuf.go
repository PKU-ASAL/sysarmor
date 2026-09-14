package policy

import (
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	policyv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/policy/v1"
)

func DetectionProto(value domainpolicy.Policy) *policyv1.DetectionPolicy {
	return &policyv1.DetectionPolicy{
		EndpointRules: append([]string(nil), value.EndpointRules...),
		CloudRules:    append([]string(nil), value.CloudRules...),
		Converge:      convergeProto(value.Converge), Rarity: rarityProto(value.Rarity),
	}
}

func convergeProto(value *domainpolicy.ConvergeParams) *policyv1.ConvergeParams {
	if value == nil {
		return nil
	}
	return &policyv1.ConvergeParams{
		Mode: value.Mode, TopK: value.TopK, MaxPathHops: value.MaxPathHops,
		AdditiveRiskThreshold: value.AdditiveRiskThreshold, CrossLineage: value.CrossLineage,
	}
}

func rarityProto(value *domainpolicy.RarityParams) *policyv1.RarityParams {
	if value == nil {
		return nil
	}
	return &policyv1.RarityParams{
		CmsWidth: value.CMSWidth, CmsDepth: value.CMSDepth,
		BaselineWindowNs: value.BaselineWindowNS,
	}
}
