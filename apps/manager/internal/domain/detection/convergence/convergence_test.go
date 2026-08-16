package convergence

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestDecideUsesAdditiveThreshold(t *testing.T) {
	decision := Decide(map[string][]domaintelemetry.Signal{"exec": {{BaseRisk: 60, Stage: domaintelemetry.SignalStageConclusion}, {BaseRisk: 45, Stage: domaintelemetry.SignalStageCandidate}}}, nil,
		&detection.Policy{Converge: &detection.ConvergePolicy{Mode: "additive_threshold", AdditiveRiskThreshold: 100}})
	if !decision.Incident || decision.Method != "additive_threshold" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestDecideAdditiveThresholdDoesNotConvergeCandidates(t *testing.T) {
	decision := Decide(map[string][]domaintelemetry.Signal{"model_anomaly": {
		{BaseRisk: 60, Stage: domaintelemetry.SignalStageCandidate, DetectorKind: domaintelemetry.DetectorKindModel},
		{BaseRisk: 60, Stage: domaintelemetry.SignalStageCandidate, DetectorKind: domaintelemetry.DetectorKindModel},
	}}, nil, &detection.Policy{Converge: &detection.ConvergePolicy{Mode: "additive_threshold", AdditiveRiskThreshold: 100}})
	if decision.Incident {
		t.Fatalf("candidate-only decision = %+v", decision)
	}
}

func TestDecideRecognizesConclusionAndCrossLineageSignals(t *testing.T) {
	conclusion := Decide(map[string][]domaintelemetry.Signal{"reverse_shell_pattern": {{Stage: domaintelemetry.SignalStageConclusion}}}, nil, nil)
	if !conclusion.Incident || conclusion.Controls[0] != "conclusion_reverse_shell" {
		t.Fatalf("conclusion decision = %+v", conclusion)
	}
	cross := Decide(nil, []domaintelemetry.Signal{{Name: "dropped_payload_executed_and_connects", Stage: domaintelemetry.SignalStageConclusion, CrossLineage: true}}, nil)
	if !cross.Incident || cross.Controls[0] != "cross_lineage_payload_connect" {
		t.Fatalf("cross-lineage decision = %+v", cross)
	}
}

func TestDecideDoesNotConvergeCrossLineageCandidate(t *testing.T) {
	decision := Decide(nil, []domaintelemetry.Signal{{
		Name: "dropped_payload_executed_and_connects", Stage: domaintelemetry.SignalStageCandidate, CrossLineage: true,
	}}, nil)
	if decision.Incident {
		t.Fatalf("cross-lineage candidate decision = %+v", decision)
	}
}

func TestDecideDoesNotConvergeCandidateSignal(t *testing.T) {
	decision := Decide(map[string][]domaintelemetry.Signal{"reverse_shell_pattern": {{Stage: domaintelemetry.SignalStageCandidate}}}, nil, nil)
	if decision.Incident {
		t.Fatalf("candidate decision = %+v", decision)
	}
}

func TestDecideHonorsCrossLineagePolicy(t *testing.T) {
	cloud := []domaintelemetry.Signal{{Name: "dropped_payload_executed_and_connects", Stage: domaintelemetry.SignalStageConclusion, CrossLineage: true}}
	decision := Decide(nil, cloud, &detection.Policy{Converge: &detection.ConvergePolicy{CrossLineage: false}})
	if decision.Incident {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestDecideUsesDefaultAdditiveThreshold(t *testing.T) {
	policy := &detection.Policy{Converge: &detection.ConvergePolicy{Mode: "additive_threshold"}}
	decision := Decide(map[string][]domaintelemetry.Signal{"exec": {{BaseRisk: 99}}}, nil, policy)
	if decision.Incident || decision.Method != "additive_threshold" {
		t.Fatalf("decision = %+v", decision)
	}
}
