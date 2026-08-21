package contracts

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestResolvePolicyBundleKeepsRuleOnlyCollectionTargeted(t *testing.T) {
	resolved, err := ResolvePolicyBundle([]byte(`{
		"tenant_id":"tenant-a","policy_id":"policy-a","version":1,
		"protection_mode":"rule-only",
		"collection":{"behaviors":["process.exec"]},
		"detection":{"rulesets":[{"ref":"ruleset:a","version":"v1"}]},
		"telemetry":{},"response_policy":{}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ProtectionMode != "rule-only" {
		t.Fatalf("protection mode = %q", resolved.ProtectionMode)
	}
	assertCollectionBehaviors(t, resolved.EndpointDocument, []string{"process.exec"})
	if strings.Contains(string(resolved.EndpointDocument), "protection_mode") {
		t.Fatalf("endpoint document leaks Manager mode: %s", resolved.EndpointDocument)
	}
}

func TestResolvePolicyBundleBuildsLearningCollection(t *testing.T) {
	resolved, err := ResolvePolicyBundle([]byte(`{
		"tenant_id":"tenant-a","policy_id":"policy-a","version":2,
		"protection_mode":"learning-only",
		"collection":{"behaviors":["file.read"]},
		"detection":{"learning_model":{"ref":"model:a","version":"2","digest":"sha256:abc"}},
		"telemetry":{},"response_policy":{}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	assertCollectionBehaviors(t, resolved.EndpointDocument, []string{
		"file.read", "process.exec", "process.exit", "process.fork", "file.write", "network.connect",
	})
}

func TestResolvePolicyBundleRejectsLearningOnlyEnforcement(t *testing.T) {
	_, err := ResolvePolicyBundle([]byte(`{
		"policy_id":"policy-a","version":2,
		"protection_mode":"learning-only",
		"collection":{"behaviors":[]},
		"detection":{"learning_model":{"ref":"model:a","version":"2","digest":"sha256:abc"}},
		"telemetry":{},"response_policy":{"allowed_modes":["enforce"]}
	}`))
	if err == nil || !strings.Contains(err.Error(), "observe-only") {
		t.Fatalf("ResolvePolicyBundle error = %v", err)
	}
}

func TestResolvePolicyBundleRejectsMissingModeSectionsAndCapabilityMismatch(t *testing.T) {
	tests := []string{
		`{"policy_id":"p","version":1,"collection":{},"detection":{"rulesets":[{"ref":"ruleset:a"}]},"telemetry":{},"response_policy":{}}`,
		`{"policy_id":"p","version":1,"protection_mode":"rule-only","collection":{},"detection":{"rulesets":[{"ref":"ruleset:a"}]},"telemetry":{},"response_policy":{},"mode":"observe"}`,
		`{"policy_id":"p","version":1,"protection_mode":"rule-only","detection":{"rulesets":[{"ref":"ruleset:a"}]},"telemetry":{},"response_policy":{}}`,
		`{"policy_id":"p","version":1,"protection_mode":"rule-only","collection":{},"detection":{"learning_model":{"ref":"model:a","version":"1","digest":"sha256:a"}},"telemetry":{},"response_policy":{}}`,
	}
	for _, document := range tests {
		if _, err := ResolvePolicyBundle([]byte(document)); err == nil {
			t.Fatalf("ResolvePolicyBundle(%s) succeeded", document)
		}
	}
}

func assertCollectionBehaviors(t *testing.T, document []byte, want []string) {
	t.Helper()
	var endpoint struct {
		Collection struct {
			Behaviors []json.RawMessage `json:"behaviors"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(document, &endpoint); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(endpoint.Collection.Behaviors))
	for _, raw := range endpoint.Collection.Behaviors {
		var behavior string
		if err := json.Unmarshal(raw, &behavior); err != nil {
			t.Fatalf("behavior %s is not a string", raw)
		}
		got = append(got, behavior)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("collection behaviors = %v, want %v", got, want)
	}
}
