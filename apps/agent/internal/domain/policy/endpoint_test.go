package policy

import (
	"testing"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
)

func TestDefaultPolicyBuildsObserveOnlyEndpointPolicy(t *testing.T) {
	value := DefaultPolicy("tenant-a")
	endpoint := value.EndpointPolicy()

	if endpoint.PolicyID != DefaultPolicyID || endpoint.Version != DefaultPolicyVersion {
		t.Fatalf("endpoint identity = %s@%d", endpoint.PolicyID, endpoint.Version)
	}
	if endpoint.Detection.Mode != "observe" || !endpoint.Collection.ObserveOnly {
		t.Fatalf("endpoint is not observe-only: %+v", endpoint)
	}
	if len(endpoint.Response.AllowedModes) != 1 || endpoint.Response.AllowedModes[0] != domainresponse.ModeObserve {
		t.Fatalf("response modes = %v", endpoint.Response.AllowedModes)
	}
}

func TestNormalizeDetectionDefaultsIdentityModeAndRuleSetVersion(t *testing.T) {
	enabled := true
	value := NormalizeDetectionPolicy(DetectionPolicy{
		RuleSets: []RuleSetRef{{Ref: "ruleset:a", Enabled: &enabled}},
	})

	if value.PolicyID != "default-endpoint-detection" || value.Version != 1 {
		t.Fatalf("detection identity = %s@%d", value.PolicyID, value.Version)
	}
	if value.Mode != "observe" || value.RuleSets[0].Version != "latest" {
		t.Fatalf("normalized detection = %+v", value)
	}
}

func TestDefaultManagedPolicyPublishesVersionedRuleSet(t *testing.T) {
	value := DefaultManagedPolicy("tenant-a")

	if len(value.Detection.RuleSets) != 1 {
		t.Fatalf("rule sets = %+v", value.Detection.RuleSets)
	}
	ruleSet := value.Detection.RuleSets[0]
	if ruleSet.Ref != DefaultRuleSetRef || ruleSet.Version != DefaultRuleSetVersion || ruleSet.Enabled == nil || !*ruleSet.Enabled {
		t.Fatalf("managed rule set = %+v", ruleSet)
	}
}
