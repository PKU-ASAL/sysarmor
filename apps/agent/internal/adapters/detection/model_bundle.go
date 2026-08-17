package detection

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	domainmodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/model"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

const maxModelBundleBytes = 8 << 20

type tokenVectorDocument struct {
	Token  string    `json:"token"`
	Vector []float64 `json:"vector"`
}

type subwordVectorDocument struct {
	Bucket uint32    `json:"bucket"`
	Vector []float64 `json:"vector"`
}

type embeddingDocument struct {
	Dimension   int                     `json:"dimension"`
	MinN        int                     `json:"min_n"`
	MaxN        int                     `json:"max_n"`
	BucketCount int                     `json:"bucket_count"`
	Tokens      []tokenVectorDocument   `json:"tokens"`
	Subwords    []subwordVectorDocument `json:"subwords"`
}

type weightedValueDocument struct {
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
}

type rarityDocument struct {
	DefaultFile    float64                 `json:"default_file"`
	DefaultNetwork float64                 `json:"default_network"`
	Files          []weightedValueDocument `json:"files"`
	Networks       []weightedValueDocument `json:"networks"`
}

type vaeDocument struct {
	InputDimension  int       `json:"input_dimension"`
	HiddenDimension int       `json:"hidden_dimension"`
	LatentDimension int       `json:"latent_dimension"`
	EncoderWeights  []float64 `json:"encoder_weights"`
	EncoderBias     []float64 `json:"encoder_bias"`
	MeanWeights     []float64 `json:"mean_weights"`
	MeanBias        []float64 `json:"mean_bias"`
	LogVarWeights   []float64 `json:"logvar_weights"`
	LogVarBias      []float64 `json:"logvar_bias"`
	DecoderWeights  []float64 `json:"decoder_weights"`
	DecoderBias     []float64 `json:"decoder_bias"`
	OutputWeights   []float64 `json:"output_weights"`
	OutputBias      []float64 `json:"output_bias"`
}

type stabilityDocument struct {
	Default   float64                 `json:"default"`
	Processes []weightedValueDocument `json:"processes"`
}

type modelBundleDocument struct {
	ModelRef            string            `json:"model_ref"`
	ModelVersion        string            `json:"model_version"`
	ModelDigest         string            `json:"model_digest"`
	FeatureSchema       string            `json:"feature_schema"`
	PreprocessorVersion string            `json:"preprocessor_version"`
	Embedding           embeddingDocument `json:"embedding"`
	Rarity              rarityDocument    `json:"rarity"`
	VAE                 vaeDocument       `json:"vae"`
	Stability           stabilityDocument `json:"stability"`
	Threshold           float64           `json:"threshold"`
	PayloadDigest       string            `json:"payload_digest"`
	SignatureAlg        string            `json:"signature_alg,omitempty"`
	KeyID               string            `json:"key_id,omitempty"`
	Signature           string            `json:"signature,omitempty"`
}

func LoadModelBundle(path string, trustedKeys map[string]ed25519.PublicKey) (ports.ProfileDetector, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := readModelBundle(path)
	if err != nil {
		return nil, fmt.Errorf("read learning model bundle: %w", err)
	}
	detector, err := decodeModelBundle(raw, trustedKeys)
	if err != nil {
		return nil, fmt.Errorf("load learning model bundle: %w", err)
	}
	return detector, nil
}

func readModelBundle(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxModelBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxModelBundleBytes {
		return nil, fmt.Errorf("model bundle exceeds %d bytes", maxModelBundleBytes)
	}
	return raw, nil
}

func decodeModelBundle(raw []byte, trustedKeys map[string]ed25519.PublicKey) (ports.ProfileDetector, error) {
	document, err := parseModelBundle(raw)
	if err != nil {
		return nil, err
	}
	if err := verifyModelBundle(document, trustedKeys); err != nil {
		return nil, err
	}
	return domainmodel.NewDetector(document.bundle())
}

func parseModelBundle(raw []byte) (modelBundleDocument, error) {
	if err := rejectDuplicateFields(raw); err != nil {
		return modelBundleDocument{}, err
	}
	var document modelBundleDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return modelBundleDocument{}, fmt.Errorf("decode model bundle: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return modelBundleDocument{}, err
	}
	return document, nil
}

func rejectDuplicateFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil {
		return fmt.Errorf("decode model bundle: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object field name is invalid")
			}
			if key != strings.ToLower(key) {
				return fmt.Errorf("field %q must use canonical lowercase spelling", key)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	_, err = decoder.Token()
	return err
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode model bundle: trailing JSON value")
		}
		return fmt.Errorf("decode model bundle: %w", err)
	}
	return nil
}

func SignModelBundle(raw []byte, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	document, err := parseModelBundle(raw)
	if err != nil {
		return nil, err
	}
	if err := verifyModelDigests(document); err != nil {
		return nil, err
	}
	if _, err := domainmodel.NewDetector(document.bundle()); err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyID) == "" || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("valid model signing key ID and Ed25519 private key are required")
	}
	document.SignatureAlg, document.KeyID = "ed25519", strings.TrimSpace(keyID)
	document.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signedModelBundleBytes(document.PayloadDigest)))
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode signed model bundle: %w", err)
	}
	return append(encoded, '\n'), nil
}

func (document modelBundleDocument) bundle() domainmodel.Bundle {
	return domainmodel.Bundle{
		ModelRef: document.ModelRef, ModelVersion: document.ModelVersion, ModelDigest: document.ModelDigest,
		FeatureSchema: document.FeatureSchema, PreprocessorVersion: document.PreprocessorVersion,
		Embedding: domainmodel.Embedding{
			Dimension: document.Embedding.Dimension, MinN: document.Embedding.MinN,
			MaxN: document.Embedding.MaxN, BucketCount: document.Embedding.BucketCount,
			Tokens: tokenVectors(document.Embedding.Tokens), Subwords: subwordVectors(document.Embedding.Subwords),
		},
		Rarity: domainmodel.Rarity{
			DefaultFile: float32(document.Rarity.DefaultFile), DefaultNetwork: float32(document.Rarity.DefaultNetwork),
			Files: weightedValues(document.Rarity.Files), Networks: weightedValues(document.Rarity.Networks),
		},
		VAE: domainmodel.VAE{
			InputDimension: document.VAE.InputDimension, HiddenDimension: document.VAE.HiddenDimension, LatentDimension: document.VAE.LatentDimension,
			EncoderWeights: floats32(document.VAE.EncoderWeights), EncoderBias: floats32(document.VAE.EncoderBias),
			MeanWeights: floats32(document.VAE.MeanWeights), MeanBias: floats32(document.VAE.MeanBias),
			LogVarWeights: floats32(document.VAE.LogVarWeights), LogVarBias: floats32(document.VAE.LogVarBias),
			DecoderWeights: floats32(document.VAE.DecoderWeights), DecoderBias: floats32(document.VAE.DecoderBias),
			OutputWeights: floats32(document.VAE.OutputWeights), OutputBias: floats32(document.VAE.OutputBias),
		},
		Stability: domainmodel.Stability{Default: float32(document.Stability.Default), Processes: weightedValues(document.Stability.Processes)},
		Threshold: float32(document.Threshold),
	}
}

func tokenVectors(values []tokenVectorDocument) []domainmodel.TokenVector {
	result := make([]domainmodel.TokenVector, len(values))
	for index, value := range values {
		result[index] = domainmodel.TokenVector{Token: value.Token, Vector: floats32(value.Vector)}
	}
	return result
}

func subwordVectors(values []subwordVectorDocument) []domainmodel.SubwordVector {
	result := make([]domainmodel.SubwordVector, len(values))
	for index, value := range values {
		result[index] = domainmodel.SubwordVector{Bucket: value.Bucket, Vector: floats32(value.Vector)}
	}
	return result
}

func weightedValues(values []weightedValueDocument) []domainmodel.WeightedValue {
	result := make([]domainmodel.WeightedValue, len(values))
	for index, value := range values {
		result[index] = domainmodel.WeightedValue{Value: value.Value, Weight: float32(value.Weight)}
	}
	return result
}

func floats32(values []float64) []float32 {
	result := make([]float32, len(values))
	for index, value := range values {
		result[index] = float32(value)
	}
	return result
}

func verifyModelBundle(document modelBundleDocument, trustedKeys map[string]ed25519.PublicKey) error {
	if err := verifyModelDigests(document); err != nil {
		return err
	}
	return verifyModelSignature(document, trustedKeys)
}

func verifyModelDigests(document modelBundleDocument) error {
	if document.PayloadDigest == "" {
		return fmt.Errorf("model payload digest is required")
	}
	payloadSum := sha256.Sum256(digestMaterial(document, true))
	if document.PayloadDigest != "sha256:"+hex.EncodeToString(payloadSum[:]) {
		return fmt.Errorf("model payload digest mismatch")
	}
	modelSum := sha256.Sum256(digestMaterial(document, false))
	if document.ModelDigest != "sha256:"+hex.EncodeToString(modelSum[:]) {
		return fmt.Errorf("model digest mismatch")
	}
	return nil
}

func verifyModelSignature(document modelBundleDocument, trustedKeys map[string]ed25519.PublicKey) error {
	if document.SignatureAlg != "ed25519" {
		return fmt.Errorf("unsupported model signature_alg %q", document.SignatureAlg)
	}
	key := trustedKeys[strings.TrimSpace(document.KeyID)]
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("model signature key %q is not trusted", document.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(document.Signature)
	if err != nil {
		return fmt.Errorf("decode model signature: %w", err)
	}
	if !ed25519.Verify(key, signedModelBundleBytes(document.PayloadDigest), signature) {
		return fmt.Errorf("model signature verification failed")
	}
	return nil
}

func signedModelBundleBytes(payloadDigest string) []byte {
	return []byte("sysarmor.learning-model/v2\n" + payloadDigest)
}

func digestMaterial(document modelBundleDocument, includeModelDigest bool) []byte {
	purpose := "sysarmor.learning-model/model-digest/v2"
	if includeModelDigest {
		purpose = "sysarmor.learning-model/payload-digest/v2"
	}
	material := appendLengthPrefixed(nil, purpose)
	for _, value := range []string{document.ModelRef, document.ModelVersion, document.FeatureSchema, document.PreprocessorVersion} {
		material = appendLengthPrefixed(material, value)
	}
	if includeModelDigest {
		material = appendLengthPrefixed(material, document.ModelDigest)
	}
	material = appendEmbedding(material, document.Embedding)
	material = appendRarity(material, document.Rarity)
	material = appendVAE(material, document.VAE)
	material = appendFloat32(material, float32(document.Stability.Default))
	material = appendWeightedValues(material, document.Stability.Processes)
	return appendFloat32(material, float32(document.Threshold))
}

func appendEmbedding(target []byte, value embeddingDocument) []byte {
	target = appendUint32(target, uint32(value.Dimension))
	target = appendUint32(target, uint32(value.MinN))
	target = appendUint32(target, uint32(value.MaxN))
	target = appendUint32(target, uint32(value.BucketCount))
	target = appendUint32(target, uint32(len(value.Tokens)))
	for _, token := range value.Tokens {
		target = appendLengthPrefixed(target, token.Token)
		target = appendFloat32Slice(target, token.Vector)
	}
	target = appendUint32(target, uint32(len(value.Subwords)))
	for _, subword := range value.Subwords {
		target = appendUint32(target, subword.Bucket)
		target = appendFloat32Slice(target, subword.Vector)
	}
	return target
}

func appendRarity(target []byte, value rarityDocument) []byte {
	target = appendFloat32(target, float32(value.DefaultFile))
	target = appendFloat32(target, float32(value.DefaultNetwork))
	target = appendWeightedValues(target, value.Files)
	return appendWeightedValues(target, value.Networks)
}

func appendVAE(target []byte, value vaeDocument) []byte {
	target = appendUint32(target, uint32(value.InputDimension))
	target = appendUint32(target, uint32(value.HiddenDimension))
	target = appendUint32(target, uint32(value.LatentDimension))
	for _, values := range [][]float64{
		value.EncoderWeights, value.EncoderBias, value.MeanWeights, value.MeanBias,
		value.LogVarWeights, value.LogVarBias, value.DecoderWeights, value.DecoderBias,
		value.OutputWeights, value.OutputBias,
	} {
		target = appendFloat32Slice(target, values)
	}
	return target
}

func appendWeightedValues(target []byte, values []weightedValueDocument) []byte {
	target = appendUint32(target, uint32(len(values)))
	for _, value := range values {
		target = appendLengthPrefixed(target, value.Value)
		target = appendFloat32(target, float32(value.Weight))
	}
	return target
}

func appendLengthPrefixed(target []byte, value string) []byte {
	target = appendUint32(target, uint32(len(value)))
	return append(target, value...)
}

func appendUint32(target []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendFloat32(target []byte, value float32) []byte {
	return appendUint32(target, math.Float32bits(value))
}

func appendFloat32Slice(target []byte, values []float64) []byte {
	target = appendUint32(target, uint32(len(values)))
	for _, value := range values {
		target = appendFloat32(target, float32(value))
	}
	return target
}
