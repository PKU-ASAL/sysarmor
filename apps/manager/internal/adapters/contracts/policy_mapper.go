package contracts

import (
	"encoding/json"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
)

func DetectionPolicyFromDocument(document []byte) (detection.Policy, error) {
	var value struct {
		EndpointRules []string `json:"endpoint_rules"`
		CloudRules    []string `json:"cloud_rules"`
		Converge      *struct {
			Mode                  string `json:"mode"`
			CrossLineage          bool   `json:"cross_lineage"`
			AdditiveRiskThreshold uint32 `json:"additive_risk_threshold"`
		} `json:"converge"`
	}
	if err := json.Unmarshal(document, &value); err != nil {
		return detection.Policy{}, fmt.Errorf("decode detection policy: %w", err)
	}
	result := detection.Policy{EndpointRules: value.EndpointRules, CloudRules: value.CloudRules}
	if value.Converge != nil {
		result.Converge = &detection.ConvergePolicy{
			Mode: value.Converge.Mode, CrossLineage: value.Converge.CrossLineage,
			AdditiveRiskThreshold: value.Converge.AdditiveRiskThreshold,
		}
	}
	return result, nil
}
