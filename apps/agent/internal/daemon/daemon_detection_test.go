package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/event/normalize"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestDetectionSuppressionConversion(t *testing.T) {
	got := detectionSuppression(agentcontent.RuntimeSuppression{
		Within: "5m",
		By:     []string{"process.stable_id", "file.path"},
	})
	if got.Within != 5*time.Minute || !slices.Equal(got.By, []string{"process.stable_id", "file.path"}) {
		t.Fatalf("suppression = %+v", got)
	}
}

func TestApplySupervisorHealthMarksSensorDegraded(t *testing.T) {
	sensor := contract.Health{Backend: "tetragon", Running: true, PolicyLoaded: true, RestartCount: 2}
	got := applySupervisorHealth(sensor, sensorruntime.SupervisorStatus{State: "degraded", LastError: "apply: unavailable", RestartCount: 3})
	if got.Running || got.LastError != "apply: unavailable" || got.RestartCount != 5 {
		t.Fatalf("sensor health = %+v", got)
	}
}

func TestResolveSensorHealthKeepsHealthAvailableWhenSensorFails(t *testing.T) {
	status := sensorruntime.SupervisorStatus{State: "degraded", LastError: "apply: unavailable", RestartCount: 2}
	got, err := resolveSensorHealth(contract.Health{}, errors.New("health unavailable"), &status, "tetragon")
	if err != nil || got.Backend != "tetragon" || got.Running || !strings.Contains(got.LastError, "health unavailable") {
		t.Fatalf("sensor health = %+v err=%v", got, err)
	}
}

func TestDetectionConditionTreeConversion(t *testing.T) {
	node := &agentcontent.RuntimeConditionNode{Any: []agentcontent.RuntimeConditionNode{
		{Condition: &agentcontent.RuntimeCondition{Field: "process.binary_name", Op: "in", Ref: "ctx:test-tools"}},
		{Not: &agentcontent.RuntimeConditionNode{Condition: &agentcontent.RuntimeCondition{Field: "socket.port", Op: "in", Values: []string{"80"}}}},
		{All: []agentcontent.RuntimeConditionNode{
			{Condition: &agentcontent.RuntimeCondition{Field: "behavior", Op: "eq", Value: "process.exec"}},
		}},
	}}
	got := detectionConditionNode(node)
	if got == nil || len(got.Any) != 3 || got.Any[0].Condition == nil || got.Any[1].Not == nil || len(got.Any[2].All) != 1 {
		t.Fatalf("condition tree = %+v", got)
	}
	if got.All != nil || got.Not != nil || got.Condition != nil {
		t.Fatalf("any node gained unrelated kinds: %+v", got)
	}
	if got.Any[0].All != nil || got.Any[0].Any != nil || got.Any[0].Not != nil {
		t.Fatalf("condition leaf gained unrelated kinds: %+v", got.Any[0])
	}
	if got.Any[0].Condition.Ref != "ctx:test-tools" || !slices.Equal(got.Any[1].Not.Condition.Values, []string{"80"}) {
		t.Fatalf("condition tree leaves = %+v", got)
	}
	if got.Any[2].Any != nil || got.Any[2].Not != nil || got.Any[2].Condition != nil {
		t.Fatalf("all node gained unrelated kinds: %+v", got.Any[2])
	}
}

func TestDetectionCorrelateConversion(t *testing.T) {
	got := detectionCorrelate(agentcontent.RuntimeCorrelate{
		Within: "2m", By: []string{"lineage_id"},
		Facts: []agentcontent.RuntimeFact{
			{ID: "change", Events: []string{"file.write", "file.chmod"}},
			{ID: "run", Event: "process.exec", Conditions: []agentcontent.RuntimeCondition{{Field: "process.binary", Op: "exists"}}},
		},
	})
	if got.Within != 2*time.Minute || got.WithinText != "2m" || !slices.Equal(got.By, []string{"lineage_id"}) || len(got.Facts) != 2 {
		t.Fatalf("correlate = %+v", got)
	}
	if !slices.Equal(got.Facts[0].Events, []string{"file.write", "file.chmod"}) || got.Facts[1].Event != "process.exec" || len(got.Facts[1].Conditions) != 1 {
		t.Fatalf("facts = %+v", got.Facts)
	}
}

const testCollectionPolicyJSON = `{"behaviors":["process.exec","process.exit","process.fork","file.read","file.write","network.connect"],"observe_only":true}
`

func appendEndpointEventForTest(t testing.TB, runner *AgentRuntime, bus *telemetry.Bus, norm *normalize.Normalizer, ev contract.EventEnvelope) *dataplanev1.DataBatch {
	t.Helper()
	batch, err := NewEndpointRuntime(runner, norm).ProcessEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	commitEndpointBatchForTest(t, runner, bus, batch)
	return batch
}

func appendEndpointSignalsForTest(t testing.TB, runner *AgentRuntime, bus *telemetry.Bus, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	t.Helper()
	batch, err := NewEndpointRuntime(runner, nil).ProcessSignals(signals)
	if err != nil {
		t.Fatal(err)
	}
	commitEndpointBatchForTest(t, runner, bus, batch)
	return batch
}

func commitEndpointBatchForTest(t testing.TB, runner *AgentRuntime, bus *telemetry.Bus, batch *dataplanev1.DataBatch) {
	t.Helper()
	if runner.localStore == nil {
		if bus != nil {
			bus.PublishBatch(batch)
		}
		return
	}
	batcher := telemetry.NewBatcher(runner.newDataBatch, 1, time.Hour, 1)
	batcher.Add(batch)
	batch = <-batcher.Batches()
	batcher.CloseAndFlush("test")
	sender := &localStoreBatchSender{store: runner.localStore}
	if bus != nil {
		sender.onCommit = bus.PublishBatch
	}
	if _, err := sender.SendBatch(batch); err != nil {
		t.Fatalf("commit endpoint batch: %v", err)
	}
}

func installTestDetection(t testing.TB, runner *AgentRuntime) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "deployments", "agent", "content", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.contentStore().Apply(string(raw), true, false); err != nil {
			t.Fatalf("load test content %s: %v", path, err)
		}
	}
	policy := policymodel.DefaultPolicy("default")
	policy.Detection = &policymodel.DetectionPolicy{
		PolicyID: "daemon-test-detection", Version: 1, Mode: "observe",
		RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:cep-endpoint"}},
	}
	if report, ok := runner.tryApplyRuntimePolicy(policy); !ok {
		t.Fatalf("install test detection: %+v", report)
	}
}
