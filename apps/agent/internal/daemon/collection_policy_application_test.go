package daemon

import (
	"encoding/json"
	"slices"
	"testing"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestCollectionReportDetailsPreserveCompileAndCoverageWarnings(t *testing.T) {
	details := collectionReportDetails(
		contract.CollectionCompileReport{Backend: "fake", GeneratedPolicyHash: "hash-a", Warnings: []string{"compile warning"}},
		detection.CoverageReport{Status: "degraded", Warnings: []string{"coverage warning"}},
	)
	for _, want := range []string{"generated_policy_hash=hash-a", "warning=compile warning", "coverage_warning=coverage warning"} {
		if !slices.Contains(details, want) {
			t.Fatalf("details=%v missing %q", details, want)
		}
	}
}

func TestCollectionProductionPathPersistsUnifiedEndpointAfterSensorApply(t *testing.T) {
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
	endpoint := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, endpoint); err != nil {
		t.Fatal(err)
	}
	sensor := &recordingCollectionSensor{healthOnlySensor: healthOnlySensor{health: contract.Health{Backend: "fake"}}}
	runner := newEndpointPolicyRunner(t, store, sensor)
	runner.Config.Sensor = config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}}
	runner.setEndpointPolicy(endpoint)
	controller := newApplicationPolicyController(runner, sensorruntime.New(sensor), nil)

	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "collection", Source: agentcontrol.PolicySourceStandalone,
		Context:  agentcontrol.RequestContext{Scope: &agentcontrol.Scope{Type: "container", Selector: "container-a"}},
		Document: `{"policy_id":"collection-a","version":2,"behaviors":["process.exec"]}`,
	})

	if result.Status == "rejected" || len(sensor.lastIntent.Behaviors) != 1 || sensor.lastIntent.ScopeType != "container" {
		t.Fatalf("result=%+v intent=%+v", result, sensor.lastIntent)
	}
	record, ok, err := store.Policy(t.Context(), "endpoint")
	if err != nil || !ok {
		t.Fatalf("stored endpoint ok=%t err=%v", ok, err)
	}
	var persisted agentpolicy.EndpointPolicy
	if err := json.Unmarshal(record.Document, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 2 || persisted.Collection.PolicyID != "collection-a" || runner.currentEndpointPolicy().Version != 2 {
		t.Fatalf("persisted=%+v runtime=%+v", persisted, runner.currentEndpointPolicy())
	}
}
