package detection

import (
	"testing"

	domainruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestCoverageDeduplicatesMissingBehaviorSources(t *testing.T) {
	report := coverage(
		&domainpolicy.DetectionPolicy{PolicyID: "detection-a", Version: 1},
		contract.CollectionIntent{Behaviors: []string{"process.exec"}},
		[]domainruntime.RuleSpec{{
			RuleID: "credential-read", RequiredBehaviors: []string{"file.read"},
			RequiredEvents: []domainruntime.RequiredEventSpec{{Behavior: "file.read"}},
		}},
	)

	missing := report.Rules[0].MissingBehaviors
	if len(missing) != 1 || missing[0] != "file.read" {
		t.Fatalf("missing behaviors = %v", missing)
	}
}
