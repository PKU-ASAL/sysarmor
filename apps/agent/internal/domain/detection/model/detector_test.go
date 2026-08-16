package model

import (
	"math"
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestDetectorEmitsModelCandidateWithProvenance(t *testing.T) {
	detector, err := NewDetector(Bundle{
		ModelRef: "model:normal-v1", ModelVersion: "1", ModelDigest: "sha256:test", FeatureSchema: "FeatureSchemaV1",
		Mean: []float32{0, 0, 0, 0, 0, 0}, Scale: []float32{1, 1, 1, 1, 1, 1}, Threshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	signals := detector.Process(domainevent.Event{ID: "event-a", Behavior: "process.exec", SubjectPresent: true,
		Subject: domainevent.Process{Binary: "/usr/bin/python", Argv: []string{"python", "-c", "print(1)"}}, LineageID: "lineage-a"})
	if len(signals) != 1 {
		t.Fatalf("signals=%+v", signals)
	}
	signal := signals[0]
	if signal.Stage != domaindetection.SignalStageCandidate || signal.DetectorKind != domaindetection.DetectorKindModel {
		t.Fatalf("classification=%+v", signal)
	}
	if signal.ModelRef != "model:normal-v1" || signal.FeatureSchema != "FeatureSchemaV1" || signal.EventRefs[0] != "event-a" {
		t.Fatalf("provenance=%+v", signal)
	}
	if signal.LocalRarity <= 0 || signal.GlobalRarity != 0 {
		t.Fatalf("rarity=%+v, want local score only", signal)
	}
}

func TestDetectorEmitsNothingBelowThreshold(t *testing.T) {
	detector, err := NewDetector(Bundle{
		ModelRef: "model:normal-v1", ModelVersion: "1", ModelDigest: "sha256:test", FeatureSchema: "FeatureSchemaV1",
		Mean: []float32{0, 0, 0, 0, 0, 0}, Scale: []float32{1, 1, 1, 1, 1, 1}, Threshold: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signals := detector.Process(domainevent.Event{ID: "event-a", Behavior: "process.exec"}); len(signals) != 0 {
		t.Fatalf("signals=%+v", signals)
	}
}

func TestFeatureSchemaEncodesMissingBehaviorExplicitly(t *testing.T) {
	if got := Features(domainevent.Event{})[0]; got != -1 {
		t.Fatalf("missing behavior feature = %v, want -1", got)
	}
	if got := Features(domainevent.Event{Behavior: "  "})[0]; got != -1 {
		t.Fatalf("blank behavior feature = %v, want -1", got)
	}
}

func TestDetectorRejectsInvalidBundle(t *testing.T) {
	if _, err := NewDetector(Bundle{ModelRef: "model:bad", Mean: []float32{1}, Scale: []float32{1}}); err == nil {
		t.Fatal("invalid bundle accepted")
	}
}

func TestDetectorRejectsNonFiniteParameters(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Bundle)
	}{
		{name: "mean", mutate: func(bundle *Bundle) { bundle.Mean[0] = float32(math.NaN()) }},
		{name: "threshold", mutate: func(bundle *Bundle) { bundle.Threshold = float32(math.Inf(1)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := validTestBundle()
			test.mutate(&bundle)
			if _, err := NewDetector(bundle); err == nil {
				t.Fatal("NewDetector() accepted non-finite parameter")
			}
		})
	}
}

func validTestBundle() Bundle {
	return Bundle{
		ModelRef: "model:normal-v1", ModelVersion: "1", ModelDigest: "sha256:test", FeatureSchema: FeatureSchemaV1,
		Mean: []float32{0, 0, 0, 0, 0, 0}, Scale: []float32{1, 1, 1, 1, 1, 1}, Threshold: 1,
	}
}
