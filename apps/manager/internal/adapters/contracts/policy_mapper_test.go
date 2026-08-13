package contracts

import "testing"

func TestDetectionPolicyFromDocumentMapsAnalysisFields(t *testing.T) {
	policy, err := DetectionPolicyFromDocument([]byte(`{
		"endpoint_rules":["exec"],"cloud_rules":["web_shell_chain"],
		"converge":{"mode":"additive_threshold","cross_lineage":true,"additive_risk_threshold":120}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if policy.EndpointRules[0] != "exec" || policy.CloudRules[0] != "web_shell_chain" ||
		policy.Converge == nil || policy.Converge.AdditiveRiskThreshold != 120 || !policy.Converge.CrossLineage {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestDetectionPolicyFromDocumentRejectsInvalidJSON(t *testing.T) {
	if _, err := DetectionPolicyFromDocument([]byte(`{`)); err == nil {
		t.Fatal("invalid policy accepted")
	}
}
