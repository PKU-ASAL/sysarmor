package health

import "testing"

func TestEvaluateDegradesWhenLearningDetectorFails(t *testing.T) {
	snapshot := Snapshot{
		Sensor: Sensor{Running: true},
		Detection: Detection{Learning: Learning{
			Status: "degraded", LastError: "load learning model bundle: digest mismatch",
		}},
	}

	if got := Evaluate(snapshot); got != StatusDegraded {
		t.Fatalf("Evaluate() = %q, want %q", got, StatusDegraded)
	}
}

func TestEvaluateAllowsDisabledLearningDetector(t *testing.T) {
	snapshot := Snapshot{Sensor: Sensor{Running: true}, Detection: Detection{Learning: Learning{Status: "disabled"}}}

	if got := Evaluate(snapshot); got != StatusOK {
		t.Fatalf("Evaluate() = %q, want %q", got, StatusOK)
	}
}
