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

const maxModelBundleBytes = 1 << 20

type modelBundleDocument struct {
	ModelRef      string    `json:"model_ref"`
	ModelVersion  string    `json:"model_version"`
	ModelDigest   string    `json:"model_digest"`
	FeatureSchema string    `json:"feature_schema"`
	Mean          []float64 `json:"mean"`
	Scale         []float64 `json:"scale"`
	Threshold     float64   `json:"threshold"`
	PayloadDigest string    `json:"payload_digest"`
	SignatureAlg  string    `json:"signature_alg"`
	KeyID         string    `json:"key_id"`
	Signature     string    `json:"signature"`
}

func LoadModelBundle(path string, trustedKeys map[string]ed25519.PublicKey) (ports.EventDetector, error) {
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

func decodeModelBundle(raw []byte, trustedKeys map[string]ed25519.PublicKey) (ports.EventDetector, error) {
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
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode model bundle: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("decode model bundle: top-level object is required")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode model bundle: %w", err)
		}
		key := keyToken.(string)
		if !isModelBundleField(key) {
			return fmt.Errorf("decode model bundle: unknown field %q", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("decode model bundle: duplicate field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode model bundle: %w", err)
		}
	}
	return nil
}

func isModelBundleField(value string) bool {
	switch value {
	case "model_ref", "model_version", "model_digest", "feature_schema",
		"mean", "scale", "threshold", "payload_digest", "signature_alg", "key_id", "signature":
		return true
	default:
		return false
	}
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

func (document modelBundleDocument) bundle() domainmodel.Bundle {
	return domainmodel.Bundle{
		ModelRef: document.ModelRef, ModelVersion: document.ModelVersion, ModelDigest: document.ModelDigest,
		FeatureSchema: document.FeatureSchema, Mean: floats32(document.Mean), Scale: floats32(document.Scale), Threshold: float32(document.Threshold),
	}
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
	return []byte("sysarmor.learning-model/v1\n" + payloadDigest)
}

func digestMaterial(document modelBundleDocument, includeModelDigest bool) []byte {
	purpose := "sysarmor.learning-model/model-digest/v1"
	if includeModelDigest {
		purpose = "sysarmor.learning-model/payload-digest/v1"
	}
	material := appendLengthPrefixed(nil, purpose)
	material = appendLengthPrefixed(material, document.ModelRef)
	material = appendLengthPrefixed(material, document.ModelVersion)
	material = appendLengthPrefixed(material, document.FeatureSchema)
	if includeModelDigest {
		material = appendLengthPrefixed(material, document.ModelDigest)
	}
	material = appendFloat32(material, float32(document.Threshold))
	material = appendFloat32Slice(material, document.Mean)
	return appendFloat32Slice(material, document.Scale)
}

func appendLengthPrefixed(target []byte, value string) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	target = append(target, size[:]...)
	return append(target, value...)
}

func appendFloat32(target []byte, value float32) []byte {
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], math.Float32bits(value))
	return append(target, bits[:]...)
}

func appendFloat32Slice(target []byte, values []float64) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(values)))
	target = append(target, size[:]...)
	for _, value := range values {
		target = appendFloat32(target, float32(value))
	}
	return target
}
