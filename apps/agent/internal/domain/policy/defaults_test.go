package policy

import "testing"

func TestDefaultDetectionPolicyContainsNoBuiltinContentRefs(t *testing.T) {
	value := DefaultDetectionPolicy()

	if len(value.RuleSets) != 0 || len(value.ContextRefs) != 0 || len(value.IOCRefs) != 0 || len(value.RuleOverrides) != 0 {
		t.Fatalf("default detection embeds content refs: %+v", value)
	}
}
