package analysis

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestAnalyzeAttackChainProducesCloudSignalsAndIncident(t *testing.T) {
	result := NewAnalyzer().Analyze(nil, []domaintelemetry.Signal{
		endpoint("web_runtime_spawns_shell", "lin-a", false, process("p-web")),
		endpoint("payload_dropped", "lin-a", false, file("/dev/shm/x.sh")),
		endpoint("reverse_shell_pattern", "lin-a", true, process("p-bash"), socket("10.66.0.99:443")),
	}, nil)
	if !hasCloud(result.CloudSignals, "dropped_payload_executed_and_connects") || !hasCloud(result.CloudSignals, "web_shell_chain") {
		t.Fatalf("cloud signals = %+v", result.CloudSignals)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Converge.Method != "rarity+causal-topk" {
		t.Fatalf("incidents = %+v", result.Incidents)
	}
}

func TestAnalyzeHonorsCrossLineagePolicy(t *testing.T) {
	signals := []domaintelemetry.Signal{
		endpointWithID("drop-a", "payload_dropped", "lin-a", false, file("/tmp/payload")),
		endpointWithID("exec-a", "suspicious_exec_connect", "lin-b", false, file("/tmp/payload"), socket("10.66.0.99:443")),
	}
	linked := NewAnalyzer().Analyze(nil, signals, nil)
	if len(linked.CloudSignals) != 1 || len(linked.CloudSignals[0].SignalRefs) != 2 {
		t.Fatalf("cloud signals = %+v, want contributing endpoint signal refs", linked.CloudSignals)
	}
	result := NewAnalyzer().Analyze(nil, signals, &detection.Policy{Converge: &detection.ConvergePolicy{CrossLineage: false}})
	if len(result.CloudSignals) != 0 || len(result.Incidents) != 0 {
		t.Fatalf("analysis = %+v", result)
	}
}

func TestAnalyzeUsesAdditiveThreshold(t *testing.T) {
	policy := &detection.Policy{Converge: &detection.ConvergePolicy{Mode: "additive_threshold", AdditiveRiskThreshold: 100}}
	result := NewAnalyzer().Analyze(nil, []domaintelemetry.Signal{
		endpoint("download", "lin-a", false, socket("10.0.0.1:80")),
		endpoint("download", "lin-a", false, socket("10.0.0.1:80")),
	}, policy)
	if len(result.Incidents) != 1 || result.Incidents[0].Converge.Method != "additive_threshold" {
		t.Fatalf("analysis = %+v", result)
	}
}

func TestAnalyzeUsesRarityBaseline(t *testing.T) {
	analyzer := NewAnalyzer()
	analyzer.SetRarityBaseline(rarity.Baseline{WorkloadCounts: map[string]map[string]uint64{
		"container:checkout": {"reverse_shell_pattern": 3},
	}})
	result := analyzer.Analyze(nil, []domaintelemetry.Signal{
		endpoint("reverse_shell_pattern", "lin-a", true, container("checkout"), process("p-bash")),
	}, nil)
	if result.Incidents[0].Converge.Score != 12.5 {
		t.Fatalf("score = %f, want 12.5", result.Incidents[0].Converge.Score)
	}
}

func TestAnalyzeIDsIgnoreCallHistoryAndInputOrder(t *testing.T) {
	analyzer := NewAnalyzer()
	signals := []domaintelemetry.Signal{
		endpoint("payload_dropped", "lin-a", false, file("/tmp/payload")),
		endpoint("suspicious_exec_connect", "lin-b", false, file("/tmp/payload"), socket("10.0.0.1:443")),
	}
	first := analyzer.Analyze(nil, signals, nil)
	second := analyzer.Analyze(nil, []domaintelemetry.Signal{signals[1], signals[0]}, nil)
	if first.CloudSignals[0].ID != second.CloudSignals[0].ID || first.Incidents[0].ID != second.Incidents[0].ID {
		t.Fatalf("first = %+v, second = %+v", first, second)
	}
}

func endpoint(name, lineage string, terminal bool, entities ...domaintelemetry.Entity) domaintelemetry.Signal {
	return endpointWithID("", name, lineage, terminal, entities...)
}

func endpointWithID(id, name, lineage string, terminal bool, entities ...domaintelemetry.Entity) domaintelemetry.Signal {
	return domaintelemetry.Signal{
		ID: id, Name: name, Where: domaintelemetry.SignalWhereEndpoint, BaseRisk: 50, GlobalRarity: 1,
		LineageID: lineage, Terminal: terminal, Entities: entities, Labels: map[string]string{"scenario": "scenario-a"},
	}
}

func process(key string) domaintelemetry.Entity {
	return domaintelemetry.Entity{Kind: "process", Key: key, Role: "subject"}
}

func file(key string) domaintelemetry.Entity {
	return domaintelemetry.Entity{Kind: "file", Key: key, Role: "object"}
}

func socket(key string) domaintelemetry.Entity {
	return domaintelemetry.Entity{Kind: "socket", Key: key, Role: "object"}
}

func container(key string) domaintelemetry.Entity {
	return domaintelemetry.Entity{Kind: "container", Key: key, Role: "scope"}
}

func hasCloud(signals []domaintelemetry.Signal, name string) bool {
	for _, signal := range signals {
		if signal.Name == name {
			return true
		}
	}
	return false
}
