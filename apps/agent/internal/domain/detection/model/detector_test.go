package model

import (
	"math"
	"slices"
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

func TestProfileFeaturesUseNaturalLanguageSentencesAndIDFWeights(t *testing.T) {
	bundle := validTestBundleV2()
	profile := domainprocess.Snapshot{
		Binary: "/bin/bash", Argv: []string{"bash", "-c", "curl example.test"},
		Files: []string{"/etc/hosts"}, Networks: []string{"10.0.0.1"},
	}
	features := profileFeatures(profile, bundle.Rarity)
	want := []featureSentence{
		{tokens: []string{"bin", "bash", "bash", "c", "curl", "example", "test"}, weight: 1},
		{tokens: []string{"etc", "hosts"}, weight: 1},
		{tokens: []string{"10", "0", "0", "1"}, weight: 1},
	}
	if !slices.EqualFunc(features, want, func(a, b featureSentence) bool {
		return a.weight == b.weight && slices.Equal(a.tokens, b.tokens)
	}) {
		t.Fatalf("features = %+v, want %+v", features, want)
	}
}

func TestTokenVectorUsesUnicodeCodePointSubwords(t *testing.T) {
	embedding := compileEmbedding(Embedding{
		Dimension: 1, MinN: 3, MaxN: 3, BucketCount: 1024,
		Subwords: []SubwordVector{{Bucket: 537, Vector: []float32{1}}, {Bucket: 611, Vector: []float32{3}}},
	})
	vector, ok := tokenVector("测试", embedding)
	if !ok || len(vector) != 1 || vector[0] != 2 {
		t.Fatalf("unicode token vector = %v ok=%v, want [2] true", vector, ok)
	}
}

func TestScoreUsesDeterministicVAEAndStabilityCorrection(t *testing.T) {
	bundle := scoringTestBundle()
	detector, err := NewDetector(bundle)
	if err != nil {
		t.Fatal(err)
	}
	score := detector.Score(domainprocess.Snapshot{Binary: "/bin/bash"})
	if math.Abs(float64(score)-math.Log(50)) > 1e-5 {
		t.Fatalf("score = %v, want %v", score, math.Log(50))
	}
	bundle.Stability.Processes[0].Weight = 2
	detector, err = NewDetector(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if corrected := detector.Score(domainprocess.Snapshot{Binary: "/bin/bash"}); math.Abs(float64(corrected)-math.Log(25)) > 1e-5 {
		t.Fatalf("stability-corrected score = %v, want %v", corrected, math.Log(25))
	}
}

func TestDetectorEmitsImmutableModelCandidateLifecycle(t *testing.T) {
	detector, err := NewDetector(scoringTestBundle())
	if err != nil {
		t.Fatal(err)
	}
	profile := domainprocess.Snapshot{
		StableID: "proc-a", ParentStableID: "proc-parent", LineageID: "lineage-a",
		Binary: "/bin/bash", Revision: 1, State: domainprocess.StateActive,
		EventRefs: []string{"event-a"}, Files: []string{"/tmp/payload"}, Labels: map[string]string{"scenario": "attack"},
	}
	first := detector.Process(profile)
	if len(first) != 1 {
		t.Fatalf("first candidates = %+v", first)
	}
	candidate := first[0]
	if candidate.Stage != domaindetection.SignalStageCandidate || candidate.DetectorKind != domaindetection.DetectorKindModel {
		t.Fatalf("classification = %+v", candidate)
	}
	if candidate.ModelRef != "model:profile-v2" || candidate.FeatureSchema != FeatureSchemaV2 || candidate.EventRefs[0] != "event-a" {
		t.Fatalf("provenance = %+v", candidate)
	}
	profile.Labels["scenario"] = "mutated"
	if candidate.Labels["scenario"] != "attack" {
		t.Fatalf("candidate labels mutated = %+v", candidate.Labels)
	}
	if repeated := detector.Process(profile); len(repeated) != 0 {
		t.Fatalf("unchanged profile emitted duplicate = %+v", repeated)
	}
	profile.Revision++
	if stable := detector.Process(profile); len(stable) != 0 {
		t.Fatalf("non-material revision emitted duplicate = %+v", stable)
	}
	profile.State = domainprocess.StateExited
	profile.EventRefs = append(profile.EventRefs, "event-exit")
	final := detector.Process(profile)
	if len(final) != 1 || final[0].ID == candidate.ID {
		t.Fatalf("exit candidate = %+v, first = %+v", final, candidate)
	}
	if candidate.EventRefs[0] != "event-a" {
		t.Fatalf("previous candidate mutated = %+v", candidate)
	}
}

func TestDetectorEmitsOnNewThresholdCrossingAndMaterialIncrease(t *testing.T) {
	detector, err := NewDetector(scoringTestBundle())
	if err != nil {
		t.Fatal(err)
	}
	profile := domainprocess.Snapshot{StableID: "proc-a", Binary: "/bin/bash", Revision: 1, State: domainprocess.StateActive, EventRefs: []string{"event-1"}}
	if candidates := detector.Process(profile); len(candidates) != 1 {
		t.Fatalf("initial candidates = %+v", candidates)
	}
	profile.Revision++
	profile.Binary = "/bin/unknown"
	if candidates := detector.Process(profile); len(candidates) != 0 {
		t.Fatalf("below-threshold candidates = %+v", candidates)
	}
	profile.Revision++
	profile.Binary = "/bin/bash"
	if candidates := detector.Process(profile); len(candidates) != 1 {
		t.Fatalf("new crossing candidates = %+v", candidates)
	}
	profile.Revision++
	profile.Files = []string{"/rare"}
	if candidates := detector.Process(profile); len(candidates) != 1 {
		t.Fatalf("material increase candidates = %+v", candidates)
	}
}

func TestDetectorBoundsEmissionState(t *testing.T) {
	detector, err := NewDetector(scoringTestBundle())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxEmissionStates; index++ {
		detector.Process(domainprocess.Snapshot{
			StableID: "proc-" + string(rune(index+1)), Binary: "/bin/bash", Revision: 1, State: domainprocess.StateActive,
		})
	}
	if len(detector.emitted) != maxEmissionStates {
		t.Fatalf("emission states = %d, want %d", len(detector.emitted), maxEmissionStates)
	}
}

func scoringTestBundle() Bundle {
	bundle := validTestBundleV2()
	bundle.Embedding.Tokens = []TokenVector{
		{Token: "bash", Vector: []float32{10, 0}},
		{Token: "payload", Vector: []float32{0, 0}},
		{Token: "rare", Vector: []float32{20, 0}},
		{Token: "tmp", Vector: []float32{0, 0}},
	}
	bundle.Embedding.Subwords = nil
	bundle.VAE.EncoderWeights = []float32{0, 0, 0, 0}
	bundle.VAE.MeanWeights = []float32{0, 0}
	bundle.VAE.DecoderWeights = []float32{0, 0}
	bundle.VAE.OutputWeights = []float32{0, 0, 0, 0}
	bundle.Stability.Processes = []WeightedValue{{Value: "bash", Weight: 1}}
	bundle.Rarity.DefaultFile, bundle.Rarity.DefaultNetwork = 1, 1
	bundle.Rarity.Files = []WeightedValue{{Value: "/rare", Weight: 1}, {Value: "/tmp/payload", Weight: 1}}
	return bundle
}
