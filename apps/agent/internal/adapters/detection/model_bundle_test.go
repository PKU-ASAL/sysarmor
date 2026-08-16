package detection

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	domainmodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/model"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestDecodeModelBundleRequiresPayloadDigest(t *testing.T) {
	document := validModelDocument()
	document.PayloadDigest = ""
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, nil); err == nil {
		t.Fatal("decodeModelBundle() accepted bundle without payload digest")
	}
}

func TestDecodeModelBundleRejectsUnsignedBundle(t *testing.T) {
	document := validModelDocument()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, nil); err == nil {
		t.Fatal("decodeModelBundle() accepted unsigned bundle")
	}
}

func TestDecodeModelBundleAcceptsTrustedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := signModelDocument(validModelDocument(), "release-test", privateKey)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err != nil {
		t.Fatalf("decodeModelBundle() error = %v", err)
	}
}

func TestSignModelBundleProducesTrustedBundle(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := validModelDocument()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignModelBundle(raw, "release-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(signed, map[string]ed25519.PublicKey{"release-test": publicKey}); err != nil {
		t.Fatalf("signed bundle validation failed: %v", err)
	}
}

func TestDecodeModelBundleRejectsRedigestedTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := signModelDocument(validModelDocument(), "release-test", privateKey)
	document.Threshold = 2
	document = refreshModelDigests(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err == nil {
		t.Fatal("decodeModelBundle() accepted redigested tampering")
	}
}

func TestDecodeModelBundleRejectsSubPrecisionTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := signModelDocument(validModelDocument(), "release-test", privateKey)
	document.Mean[0] = 0.0000004
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err == nil {
		t.Fatal("decodeModelBundle() accepted parameter tampering hidden by decimal rounding")
	}
}

func TestDecodeModelBundleRejectsProvenanceBoundaryCollision(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := validModelDocument()
	document.ModelRef, document.ModelVersion = "model:a\n1", "2"
	document = refreshModelDigests(document)
	document = signModelDocument(document, "release-test", privateKey)
	document.ModelRef, document.ModelVersion = "model:a", "1\n2"
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err == nil {
		t.Fatal("decodeModelBundle() accepted provenance boundary collision")
	}
}

func TestDecodeModelBundleRejectsUnknownFields(t *testing.T) {
	if _, err := decodeModelBundle([]byte(`{"unknown":true}`), nil); err == nil {
		t.Fatal("decodeModelBundle() accepted unknown field")
	}
}

func TestDecodeModelBundleRejectsDuplicateFields(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := signModelDocument(validModelDocument(), "release-test", privateKey)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"threshold":1`), []byte(`"threshold":1,"threshold":1`), 1)
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err == nil {
		t.Fatal("decodeModelBundle() accepted duplicate field")
	}
}

func TestDecodeModelBundleRejectsCaseInsensitiveFieldAlias(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := signModelDocument(validModelDocument(), "release-test", privateKey)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"threshold":1`), []byte(`"threshold":1,"THRESHOLD":1`), 1)
	if _, err := decodeModelBundle(raw, map[string]ed25519.PublicKey{"release-test": publicKey}); err == nil {
		t.Fatal("decodeModelBundle() accepted case-insensitive field alias")
	}
}

func TestLoadModelBundleRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxModelBundleBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelBundle(path, nil); err == nil {
		t.Fatal("LoadModelBundle() accepted oversized file")
	}
}

func TestDecodeModelBundleRejectsForgedModelDigest(t *testing.T) {
	document := validModelDocument()
	document.ModelDigest = "sha256:forged"
	payloadSum := sha256.Sum256(digestMaterial(document, true))
	document.PayloadDigest = "sha256:" + hex.EncodeToString(payloadSum[:])
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeModelBundle(raw, nil); err == nil {
		t.Fatal("decodeModelBundle() accepted forged model digest")
	}
}

func TestLoadModelBundleReturnsNilWhenPathIsEmpty(t *testing.T) {
	detector, err := LoadModelBundle("  ", nil)
	if err != nil || detector != nil {
		t.Fatalf("detector = %v, error = %v", detector, err)
	}
}

func TestLoadModelBundleRejectsInvalidExplicitBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, []byte(`{"model_ref":"model:bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadModelBundle(path, nil); err == nil {
		t.Fatal("LoadModelBundle() error = nil")
	}
}

func TestLoadModelBundleLoadsCollectedBundle(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test/data/learning/model-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document modelBundleDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document = signModelDocument(document, "release-test", privateKey)
	signed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := LoadModelBundle(path, map[string]ed25519.PublicKey{"release-test": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	signals := detector.Process(domainevent.Event{
		ID: "anomaly-001", Behavior: "process.exec", SubjectPresent: true,
		Subject: domainevent.Process{Argv: []string{"bash", "-c", "curl", "sh", "--debug"}},
		Object:  domainevent.Object{SocketAddress: "10.0.0.9:443"}, ParentStableID: "proc-unknown",
	})
	if len(signals) != 1 {
		t.Fatalf("signals = %+v", signals)
	}
	replayRaw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test/data/learning/replay-signals.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		ID          string  `json:"id"`
		LocalRarity float32 `json:"localRarity"`
	}
	if err := json.Unmarshal(replayRaw, &expected); err != nil {
		t.Fatal(err)
	}
	if signals[0].ID != expected.ID || math.Float32bits(signals[0].LocalRarity) != math.Float32bits(expected.LocalRarity) {
		t.Fatalf("Go signal = %s/%f, Python signal = %s/%f", signals[0].ID, signals[0].LocalRarity, expected.ID, expected.LocalRarity)
	}
}

func signModelDocument(document modelBundleDocument, keyID string, privateKey ed25519.PrivateKey) modelBundleDocument {
	document.SignatureAlg = "ed25519"
	document.KeyID = keyID
	document.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signedModelBundleBytes(document.PayloadDigest)))
	return document
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func validModelDocument() modelBundleDocument {
	document := modelBundleDocument{
		ModelRef: "model:normal-v1", ModelVersion: "1", FeatureSchema: domainmodel.FeatureSchemaV1,
		Mean: []float64{0, 0, 0, 0, 0, 0}, Scale: []float64{1, 1, 1, 1, 1, 1}, Threshold: 1,
	}
	modelSum := sha256.Sum256(digestMaterial(document, false))
	document.ModelDigest = "sha256:" + hex.EncodeToString(modelSum[:])
	payloadSum := sha256.Sum256(digestMaterial(document, true))
	document.PayloadDigest = "sha256:" + hex.EncodeToString(payloadSum[:])
	return document
}

func refreshModelDigests(document modelBundleDocument) modelBundleDocument {
	modelSum := sha256.Sum256(digestMaterial(document, false))
	document.ModelDigest = "sha256:" + hex.EncodeToString(modelSum[:])
	payloadSum := sha256.Sum256(digestMaterial(document, true))
	document.PayloadDigest = "sha256:" + hex.EncodeToString(payloadSum[:])
	return document
}
