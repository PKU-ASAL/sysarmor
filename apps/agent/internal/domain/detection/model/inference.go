package model

import "math"

type compiledEmbedding struct {
	dimension, minN, maxN, bucketCount int
	tokens                             map[string][]float32
	subwords                           map[uint32][]float32
}

func compileEmbedding(embedding Embedding) compiledEmbedding {
	compiled := compiledEmbedding{
		dimension: embedding.Dimension, minN: embedding.MinN, maxN: embedding.MaxN, bucketCount: embedding.BucketCount,
		tokens: make(map[string][]float32, len(embedding.Tokens)), subwords: make(map[uint32][]float32, len(embedding.Subwords)),
	}
	for _, token := range embedding.Tokens {
		compiled.tokens[token.Token] = token.Vector
	}
	for _, subword := range embedding.Subwords {
		compiled.subwords[subword.Bucket] = subword.Vector
	}
	return compiled
}

func processVector(features []featureSentence, embedding compiledEmbedding) []float32 {
	result := make([]float32, embedding.dimension)
	for _, feature := range features {
		vector := sentenceVector(feature.tokens, embedding)
		for index, value := range vector {
			result[index] += value * feature.weight
		}
	}
	return result
}

func sentenceVector(tokens []string, embedding compiledEmbedding) []float32 {
	result := make([]float32, embedding.dimension)
	count := 0
	for _, token := range tokens {
		vector, ok := tokenVector(token, embedding)
		if !ok {
			continue
		}
		addVector(result, vector)
		count++
	}
	if count > 0 {
		for index := range result {
			result[index] /= float32(count)
		}
	}
	return result
}

func tokenVector(token string, embedding compiledEmbedding) ([]float32, bool) {
	result := make([]float32, embedding.dimension)
	count := 0
	if vector, ok := embedding.tokens[token]; ok {
		addVector(result, vector)
		count++
	}
	wrapped := "<" + token + ">"
	for size := embedding.minN; size <= embedding.maxN; size++ {
		for start := 0; start+size <= len(wrapped); start++ {
			bucket := fnv1a(wrapped[start:start+size]) % uint32(embedding.bucketCount)
			if vector, ok := embedding.subwords[bucket]; ok {
				addVector(result, vector)
				count++
			}
		}
	}
	if count == 0 {
		return nil, false
	}
	for index := range result {
		result[index] /= float32(count)
	}
	return result, true
}

func addVector(target, source []float32) {
	for index, value := range source {
		target[index] += value
	}
}

func fnv1a(value string) uint32 {
	result := uint32(2166136261)
	for _, current := range []byte(value) {
		result = (result ^ uint32(current)) * 16777619
	}
	return result
}

func reconstruct(input []float32, vae VAE) []float32 {
	hidden := dense(input, vae.EncoderWeights, vae.EncoderBias, vae.HiddenDimension, true)
	mean := dense(hidden, vae.MeanWeights, vae.MeanBias, vae.LatentDimension, false)
	decoded := dense(mean, vae.DecoderWeights, vae.DecoderBias, vae.HiddenDimension, true)
	return dense(decoded, vae.OutputWeights, vae.OutputBias, vae.InputDimension, false)
}

func dense(input, weights, bias []float32, outputDimension int, relu bool) []float32 {
	result := make([]float32, outputDimension)
	for row := 0; row < outputDimension; row++ {
		value := bias[row]
		for column, inputValue := range input {
			value += weights[row*len(input)+column] * inputValue
		}
		if relu && value < 0 {
			value = 0
		}
		result[row] = value
	}
	return result
}

func reconstructionError(input, output []float32) float32 {
	var total float32
	for index, value := range input {
		difference := value - output[index]
		total += difference * difference
	}
	return total / float32(len(input))
}

func finite(value float32) bool {
	return !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}
