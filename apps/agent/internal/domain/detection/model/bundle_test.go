package model

import (
	"math"
	"testing"
)

func TestValidateBundleAcceptsFeatureSchemaV2(t *testing.T) {
	if err := validateBundle(validTestBundleV2()); err != nil {
		t.Fatalf("validateBundle() error = %v", err)
	}
}

func TestValidateBundleRejectsInvalidFeatureSchemaV2(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Bundle)
	}{
		{name: "schema", mutate: func(bundle *Bundle) { bundle.FeatureSchema = "unsupported-schema" }},
		{name: "preprocessor", mutate: func(bundle *Bundle) { bundle.PreprocessorVersion = "" }},
		{name: "embedding dimension", mutate: func(bundle *Bundle) { bundle.Embedding.Dimension = 3 }},
		{name: "token order", mutate: func(bundle *Bundle) { bundle.Embedding.Tokens[1].Token = "aa" }},
		{name: "subword bucket", mutate: func(bundle *Bundle) { bundle.Embedding.Subwords[0].Bucket = 4 }},
		{name: "file idf", mutate: func(bundle *Bundle) { bundle.Rarity.Files[0].Weight = -1 }},
		{name: "stability", mutate: func(bundle *Bundle) { bundle.Stability.Default = float32(math.NaN()) }},
		{name: "process stability", mutate: func(bundle *Bundle) { bundle.Stability.Processes[0].Weight = 0 }},
		{name: "vae matrix", mutate: func(bundle *Bundle) { bundle.VAE.OutputWeights = bundle.VAE.OutputWeights[:3] }},
		{name: "threshold", mutate: func(bundle *Bundle) { bundle.Threshold = float32(math.Inf(1)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := validTestBundleV2()
			test.mutate(&bundle)
			if err := validateBundle(bundle); err == nil {
				t.Fatal("validateBundle() accepted invalid bundle")
			}
		})
	}
}

func validTestBundleV2() Bundle {
	return Bundle{
		ModelRef: "model:profile-v2", ModelVersion: "2", ModelDigest: "sha256:test",
		FeatureSchema: FeatureSchemaV2, PreprocessorVersion: "process-profile-v1", Threshold: 1,
		Embedding: Embedding{
			Dimension: 2, MinN: 3, MaxN: 4, BucketCount: 4,
			Tokens:   []TokenVector{{Token: "bash", Vector: []float32{1, 0}}, {Token: "curl", Vector: []float32{0, 1}}},
			Subwords: []SubwordVector{{Bucket: 1, Vector: []float32{0.5, 0.5}}},
		},
		Rarity: Rarity{
			DefaultFile: 2, DefaultNetwork: 2,
			Files:    []WeightedValue{{Value: "/etc/hosts", Weight: 1}},
			Networks: []WeightedValue{{Value: "10.0.0.1", Weight: 1}},
		},
		VAE: VAE{
			InputDimension: 2, HiddenDimension: 2, LatentDimension: 1,
			EncoderWeights: []float32{1, 0, 0, 1}, EncoderBias: []float32{0, 0},
			MeanWeights: []float32{0.5, 0.5}, MeanBias: []float32{0},
			LogVarWeights: []float32{0, 0}, LogVarBias: []float32{0},
			DecoderWeights: []float32{1, 1}, DecoderBias: []float32{0, 0},
			OutputWeights: []float32{1, 0, 0, 1}, OutputBias: []float32{0, 0},
		},
		Stability: Stability{
			Default:   1,
			Processes: []WeightedValue{{Value: "bash", Weight: 1}},
		},
	}
}
