package incident

import (
	"math"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/convergence"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestBuilderCreatesIncidentWithEvidence(t *testing.T) {
	builder := NewBuilder()
	value := builder.Build(incidentEvents(), contributingSignals("a", "b"), convergence.Decision{
		Incident: true, Method: "rarity+causal-topk", Controls: []string{"conclusion_reverse_shell"},
	})
	if value.Converge.Score != 80 || value.Converge.Method != "rarity+causal-topk" {
		t.Fatalf("converge = %+v", value.Converge)
	}
	if len(value.Evidence.Edges) == 0 || len(value.ConclusionEntities) != 1 {
		t.Fatalf("incident = %+v", value)
	}
}

func TestStableIncidentIDDistinguishesNonFiniteRarity(t *testing.T) {
	builder := NewBuilder()
	decision := convergence.Decision{Method: "rarity+causal-topk"}
	nan := builder.Build(nil, []domaintelemetry.Signal{{ID: "a", LocalRarity: math.Float32frombits(0x7fc00001)}}, decision)
	infinity := builder.Build(nil, []domaintelemetry.Signal{{ID: "a", LocalRarity: float32(math.Inf(1))}}, decision)
	if nan.ID == "" || infinity.ID == "" || nan.ID == infinity.ID {
		t.Fatalf("nan ID = %q, infinity ID = %q", nan.ID, infinity.ID)
	}
}

func TestStableIncidentIDIgnoresInputOrder(t *testing.T) {
	builder := NewBuilder()
	decision := convergence.Decision{Incident: true, Method: "rarity+causal-topk"}
	signals := contributingSignals("a", "b")
	first := builder.Build(nil, signals, decision)
	second := builder.Build(nil, []domaintelemetry.Signal{signals[1], signals[0]}, decision)
	if first.ID != second.ID {
		t.Fatalf("IDs differ: %q != %q", first.ID, second.ID)
	}
}

func TestBuilderUsesInjectedRarityScorer(t *testing.T) {
	builder := &Builder{Scorer: rarity.WorkloadBaselineScorer{Baseline: rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{
		"container:checkout": {"reverse_shell_pattern": 3},
	}}}}
	value := builder.Build(nil, []domaintelemetry.Signal{{Name: "reverse_shell_pattern", BaseRisk: 80, GlobalRarity: 1,
		Entities: []domaintelemetry.Entity{{Kind: "container", Key: "checkout"}}}}, convergence.Decision{})
	if value.Converge.Score != 20 {
		t.Fatalf("score = %f, want 20", value.Converge.Score)
	}
}

func incidentEvents() []domaintelemetry.Event {
	return []domaintelemetry.Event{{
		ID: "connect", Behavior: "network.connect", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-bash"},
		Object: &domaintelemetry.ObjectRef{Kind: "socket", SocketAddress: "10.66.0.99:443"},
	}}
}

func contributingSignals(firstID, secondID string) []domaintelemetry.Signal {
	return []domaintelemetry.Signal{
		{ID: firstID, Name: "reverse_shell_pattern", BaseRisk: 80, GlobalRarity: 1, LineageID: "lin-a", Stage: domaintelemetry.SignalStageConclusion,
			Labels: map[string]string{"scenario": "scenario-a"}, Entities: []domaintelemetry.Entity{
				{Kind: "process", Key: "p-bash", Role: "subject"}, {Kind: "socket", Key: "10.66.0.99:443", Role: "object"},
			}},
		{ID: secondID, Name: "context", LineageID: "lin-b", Labels: map[string]string{"scenario": "scenario-a"}},
	}
}
