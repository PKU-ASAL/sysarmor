package processing

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestEngineAnalyzeReturnsDomainAnalysis(t *testing.T) {
	result := NewEngine().Analyze(nil, attackChainSignals())
	if !hasCloudSignal(result.CloudSignals, "dropped_payload_executed_and_connects") || len(result.Incidents) != 1 {
		t.Fatalf("analysis = %+v", result)
	}
}

func TestEngineAnalyzeWithPolicyDisablesCloudRule(t *testing.T) {
	result := NewEngine().AnalyzeWithPolicy(nil, attackChainSignals(), &detection.Policy{CloudRules: []string{"web_shell_chain"}})
	if hasCloudSignal(result.CloudSignals, "dropped_payload_executed_and_connects") {
		t.Fatalf("disabled cloud rule produced signal: %+v", result.CloudSignals)
	}
}

func TestEngineSetRarityBaselineAffectsIncidentScore(t *testing.T) {
	engine := NewEngine()
	engine.SetRarityBaseline(rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{
		"container:checkout": {"reverse_shell_pattern": 3},
	}})
	result := engine.Analyze(nil, []domaintelemetry.Signal{
		endpointSignal("reverse_shell_pattern", true, domaintelemetry.Entity{Kind: "container", Key: "checkout", Role: "scope"}),
	})
	if len(result.Incidents) != 1 || result.Incidents[0].Converge.Score != 12.5 {
		t.Fatalf("analysis = %+v", result)
	}
}

func TestNilEngineReturnsEmptyAnalysis(t *testing.T) {
	var engine *Engine
	result := engine.Analyze(nil, nil)
	if len(result.CloudSignals) != 0 || len(result.Incidents) != 0 {
		t.Fatalf("nil engine analysis = %+v", result)
	}
}

func attackChainSignals() []domaintelemetry.Signal {
	return []domaintelemetry.Signal{
		endpointSignal("web_runtime_spawns_shell", false, domaintelemetry.Entity{Kind: "process", Key: "web", Role: "subject"}),
		endpointSignal("payload_dropped", false, domaintelemetry.Entity{Kind: "file", Key: "/tmp/payload", Role: "object"}),
		endpointSignal("reverse_shell_pattern", true,
			domaintelemetry.Entity{Kind: "process", Key: "bash", Role: "subject"},
			domaintelemetry.Entity{Kind: "socket", Key: "10.0.0.1:443", Role: "object"}),
	}
}

func endpointSignal(name string, terminal bool, entities ...domaintelemetry.Entity) domaintelemetry.Signal {
	return domaintelemetry.Signal{
		Name: name, Where: domaintelemetry.SignalWhereEndpoint, BaseRisk: 50,
		GlobalRarity: 1, LineageID: "lineage-a", Terminal: terminal,
		Entities: entities, Labels: map[string]string{"scenario": "scenario-a"},
	}
}

func hasCloudSignal(signals []domaintelemetry.Signal, name string) bool {
	for _, signal := range signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}
