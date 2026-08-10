package rarity

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestWorkloadBaselineScorerUsesContainerCount(t *testing.T) {
	scorer := WorkloadBaselineScorer{Baseline: Baseline{WorkloadCounts: map[string]map[string]uint64{
		"container:checkout": {"reverse_shell": 3},
	}}}
	score := scorer.Score([]domaintelemetry.Signal{{Name: "reverse_shell", BaseRisk: 50, GlobalRarity: 1,
		Entities: []domaintelemetry.Entity{{Kind: "container", Key: "checkout"}}}})
	if score != 12.5 {
		t.Fatalf("score = %f, want 12.5", score)
	}
}

func TestBaselineObserveTracksWorkloadAndGlobalCounts(t *testing.T) {
	var baseline Baseline
	baseline.Observe([]domaintelemetry.Signal{{Name: "exec", Entities: []domaintelemetry.Entity{{Kind: "host", Key: "host-a"}}}})
	if baseline.Count("host:host-a", "exec") != 1 || baseline.Count("global", "exec") != 1 {
		t.Fatalf("baseline = %+v", baseline)
	}
}

func TestCountScorerDownweightsRepeatedSignals(t *testing.T) {
	score := CountScorer{}.Score([]domaintelemetry.Signal{
		{Name: "download", BaseRisk: 50, GlobalRarity: 1},
		{Name: "download", BaseRisk: 50, GlobalRarity: 1},
	})
	if score != 75 {
		t.Fatalf("score = %f, want 75", score)
	}
}

func TestBaselineSnapshotIsIndependent(t *testing.T) {
	baseline := Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"exec": 2}}}
	snapshot := baseline.Snapshot()
	snapshot.Add("global", "exec", 3)
	if baseline.Count("global", "exec") != 2 || snapshot.Count("global", "exec") != 5 {
		t.Fatalf("baseline = %+v, snapshot = %+v", baseline, snapshot)
	}
}

func TestRiskScorerUsesGlobalRarity(t *testing.T) {
	score := RiskScorer{}.Score([]domaintelemetry.Signal{{BaseRisk: 80, GlobalRarity: 0.5}})
	if score != 40 {
		t.Fatalf("score = %f, want 40", score)
	}
}

func TestWorkloadBaselineFallsBackToGlobal(t *testing.T) {
	scorer := WorkloadBaselineScorer{Baseline: Baseline{WorkloadCounts: map[string]map[string]uint64{
		"global": {"reverse_shell": 1},
	}}}
	if score := scorer.Score([]domaintelemetry.Signal{{Name: "reverse_shell", BaseRisk: 80, GlobalRarity: 1}}); score != 40 {
		t.Fatalf("score = %f, want 40", score)
	}
}

func TestBaselineMergeAddsCounts(t *testing.T) {
	baseline := Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"exec": 1}}}
	baseline.Merge(Baseline{WorkloadCounts: map[string]map[string]uint64{"global": {"exec": 2}}})
	if baseline.Count("global", "exec") != 3 {
		t.Fatalf("baseline = %+v", baseline)
	}
}
