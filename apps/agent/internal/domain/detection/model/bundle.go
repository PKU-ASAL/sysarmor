package model

import (
	"fmt"
	"strings"
)

const FeatureSchemaV2 = "FeatureSchemaV2"

type Bundle struct {
	ModelRef, ModelVersion, ModelDigest string
	FeatureSchema, PreprocessorVersion  string
	Embedding                           Embedding
	Rarity                              Rarity
	VAE                                 VAE
	Stability                           Stability
	Threshold                           float32
}

type TokenVector struct {
	Token  string
	Vector []float32
}

type SubwordVector struct {
	Bucket uint32
	Vector []float32
}

type Embedding struct {
	Dimension, MinN, MaxN, BucketCount int
	Tokens                             []TokenVector
	Subwords                           []SubwordVector
}

type WeightedValue struct {
	Value  string
	Weight float32
}

type Rarity struct {
	DefaultFile, DefaultNetwork float32
	Files, Networks             []WeightedValue
}

type VAE struct {
	InputDimension, HiddenDimension, LatentDimension int
	EncoderWeights, EncoderBias                      []float32
	MeanWeights, MeanBias                            []float32
	LogVarWeights, LogVarBias                        []float32
	DecoderWeights, DecoderBias                      []float32
	OutputWeights, OutputBias                        []float32
}

type Stability struct {
	Default   float32
	Processes []WeightedValue
}

func validateBundle(bundle Bundle) error {
	if strings.TrimSpace(bundle.ModelRef) == "" || strings.TrimSpace(bundle.ModelVersion) == "" || strings.TrimSpace(bundle.ModelDigest) == "" {
		return fmt.Errorf("model provenance is required")
	}
	if bundle.FeatureSchema != FeatureSchemaV2 || strings.TrimSpace(bundle.PreprocessorVersion) == "" {
		return fmt.Errorf("unsupported model bundle schema")
	}
	if err := validateEmbedding(bundle.Embedding); err != nil {
		return err
	}
	if err := validateRarity(bundle.Rarity); err != nil {
		return err
	}
	if err := validateVAE(bundle.VAE, bundle.Embedding.Dimension); err != nil {
		return err
	}
	if bundle.Stability.Default <= 0 || !finite(bundle.Stability.Default) {
		return fmt.Errorf("default process stability must be finite and positive")
	}
	if err := validateWeightedValues("process stability", bundle.Stability.Processes); err != nil {
		return err
	}
	for _, value := range bundle.Stability.Processes {
		if value.Weight == 0 {
			return fmt.Errorf("process stability weights must be positive")
		}
	}
	if !finite(bundle.Threshold) {
		return fmt.Errorf("model threshold must be finite")
	}
	return nil
}

func validateEmbedding(embedding Embedding) error {
	if embedding.Dimension <= 0 || embedding.MinN <= 0 || embedding.MaxN < embedding.MinN || embedding.BucketCount <= 0 {
		return fmt.Errorf("embedding dimensions and subword bounds are invalid")
	}
	previous := ""
	for _, token := range embedding.Tokens {
		if token.Token <= previous || strings.TrimSpace(token.Token) == "" {
			return fmt.Errorf("embedding tokens must be sorted and unique")
		}
		if err := validateVector("token vector", token.Vector, embedding.Dimension); err != nil {
			return err
		}
		previous = token.Token
	}
	var previousBucket uint32
	for index, subword := range embedding.Subwords {
		if int(subword.Bucket) >= embedding.BucketCount || index > 0 && subword.Bucket <= previousBucket {
			return fmt.Errorf("subword buckets must be sorted, unique, and in range")
		}
		if err := validateVector("subword vector", subword.Vector, embedding.Dimension); err != nil {
			return err
		}
		previousBucket = subword.Bucket
	}
	if len(embedding.Tokens)+len(embedding.Subwords) == 0 {
		return fmt.Errorf("embedding vectors are required")
	}
	return nil
}

func validateRarity(rarity Rarity) error {
	if rarity.DefaultFile <= 0 || rarity.DefaultNetwork <= 0 || !finite(rarity.DefaultFile) || !finite(rarity.DefaultNetwork) {
		return fmt.Errorf("default rarity weights must be finite and positive")
	}
	if err := validateWeightedValues("file rarity", rarity.Files); err != nil {
		return err
	}
	return validateWeightedValues("network rarity", rarity.Networks)
}

func validateWeightedValues(name string, values []WeightedValue) error {
	previous := ""
	for _, value := range values {
		if value.Value <= previous || strings.TrimSpace(value.Value) == "" {
			return fmt.Errorf("%s values must be sorted and unique", name)
		}
		if value.Weight < 0 || !finite(value.Weight) {
			return fmt.Errorf("%s weights must be finite and non-negative", name)
		}
		previous = value.Value
	}
	return nil
}

func validateVAE(vae VAE, inputDimension int) error {
	if vae.InputDimension != inputDimension || vae.HiddenDimension <= 0 || vae.LatentDimension <= 0 {
		return fmt.Errorf("VAE dimensions are invalid")
	}
	matrices := []struct {
		name   string
		values []float32
		length int
	}{
		{"encoder weights", vae.EncoderWeights, vae.HiddenDimension * vae.InputDimension},
		{"encoder bias", vae.EncoderBias, vae.HiddenDimension},
		{"mean weights", vae.MeanWeights, vae.LatentDimension * vae.HiddenDimension},
		{"mean bias", vae.MeanBias, vae.LatentDimension},
		{"log variance weights", vae.LogVarWeights, vae.LatentDimension * vae.HiddenDimension},
		{"log variance bias", vae.LogVarBias, vae.LatentDimension},
		{"decoder weights", vae.DecoderWeights, vae.HiddenDimension * vae.LatentDimension},
		{"decoder bias", vae.DecoderBias, vae.HiddenDimension},
		{"output weights", vae.OutputWeights, vae.InputDimension * vae.HiddenDimension},
		{"output bias", vae.OutputBias, vae.InputDimension},
	}
	for _, matrix := range matrices {
		if err := validateVector(matrix.name, matrix.values, matrix.length); err != nil {
			return err
		}
	}
	return nil
}

func validateVector(name string, values []float32, expected int) error {
	if len(values) != expected {
		return fmt.Errorf("%s length is %d, want %d", name, len(values), expected)
	}
	for _, value := range values {
		if !finite(value) {
			return fmt.Errorf("%s must contain only finite values", name)
		}
	}
	return nil
}

func cloneBundle(bundle Bundle) Bundle {
	bundle.Embedding.Tokens = cloneTokenVectors(bundle.Embedding.Tokens)
	bundle.Embedding.Subwords = cloneSubwordVectors(bundle.Embedding.Subwords)
	bundle.Rarity.Files = append([]WeightedValue(nil), bundle.Rarity.Files...)
	bundle.Rarity.Networks = append([]WeightedValue(nil), bundle.Rarity.Networks...)
	bundle.Stability.Processes = append([]WeightedValue(nil), bundle.Stability.Processes...)
	bundle.VAE.EncoderWeights = append([]float32(nil), bundle.VAE.EncoderWeights...)
	bundle.VAE.EncoderBias = append([]float32(nil), bundle.VAE.EncoderBias...)
	bundle.VAE.MeanWeights = append([]float32(nil), bundle.VAE.MeanWeights...)
	bundle.VAE.MeanBias = append([]float32(nil), bundle.VAE.MeanBias...)
	bundle.VAE.LogVarWeights = append([]float32(nil), bundle.VAE.LogVarWeights...)
	bundle.VAE.LogVarBias = append([]float32(nil), bundle.VAE.LogVarBias...)
	bundle.VAE.DecoderWeights = append([]float32(nil), bundle.VAE.DecoderWeights...)
	bundle.VAE.DecoderBias = append([]float32(nil), bundle.VAE.DecoderBias...)
	bundle.VAE.OutputWeights = append([]float32(nil), bundle.VAE.OutputWeights...)
	bundle.VAE.OutputBias = append([]float32(nil), bundle.VAE.OutputBias...)
	return bundle
}

func cloneTokenVectors(values []TokenVector) []TokenVector {
	result := make([]TokenVector, len(values))
	for index, value := range values {
		result[index] = TokenVector{Token: value.Token, Vector: append([]float32(nil), value.Vector...)}
	}
	return result
}

func cloneSubwordVectors(values []SubwordVector) []SubwordVector {
	result := make([]SubwordVector, len(values))
	for index, value := range values {
		result[index] = SubwordVector{Bucket: value.Bucket, Vector: append([]float32(nil), value.Vector...)}
	}
	return result
}
