package runtime

import (
	"encoding/json"
	"testing"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
)

func TestDetectionProductionPathPersistsUnifiedEndpointBeforePublish(t *testing.T) {
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
	endpoint := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, endpoint); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	runner.setEndpointPolicy(endpoint)
	result := newApplicationPolicyController(runner, nil, nil).ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "detection", Source: agentcontrol.PolicySourceStandalone,
		Document: `{"policy_id":"detection-a","version":2,"rulesets":[{"ref":"ruleset:cep-endpoint"}]}`,
	})
	if result.Status == "rejected" {
		t.Fatalf("result=%+v", result)
	}
	record, ok, err := store.Policy(t.Context(), "endpoint")
	if err != nil || !ok {
		t.Fatalf("stored endpoint ok=%t err=%v", ok, err)
	}
	var persisted agentpolicy.EndpointPolicy
	if err := json.Unmarshal(record.Document, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 2 || persisted.Detection.PolicyID != "detection-a" || runner.currentEndpointPolicy().Detection.PolicyID != "detection-a" {
		t.Fatalf("persisted=%+v runtime=%+v", persisted, runner.currentEndpointPolicy())
	}
}

func TestDetectionRejectedBuildKeepsCurrentRuntime(t *testing.T) {
	runner := newEndpointPolicyRunner(t, nil, &healthOnlySensor{})
	endpoint := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	runner.setEndpointPolicy(endpoint)
	before := runner.currentDetection()
	result := newApplicationPolicyController(runner, nil, nil).ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "detection", Source: agentcontrol.PolicySourceStandalone,
		Document: `{"policy_id":"bad","version":2,"rulesets":[{"ref":"ruleset:missing"}]}`,
	})
	if result.Status != "rejected" || runner.currentEndpointPolicy().PolicyID != "standalone" || runner.currentDetection() != before {
		t.Fatalf("result=%+v endpoint=%+v", result, runner.currentEndpointPolicy())
	}
}
