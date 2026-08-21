package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
)

func TestMergeReleaseConfigWritesPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	existingPath := writeTestFile(t, dir, "existing.yaml", "local:\n  state_path: /custom/state\ncontent:\n  path: /custom/content\n  trust_keys: old=key\n")
	releasePath := writeTestFile(t, dir, "release.yaml", "local:\n  state_path: /var/lib/sysarmor/agent\ncontent:\n  default_path: /opt/sysarmor/content\n  trust_keys: release=new-key\n")
	outputPath := filepath.Join(dir, "merged.yaml")

	if err := MergeReleaseConfig(existingPath, releasePath, outputPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `path: "/custom/content"`) || !strings.Contains(string(raw), `trust_keys: "release=new-key"`) {
		t.Fatalf("merged config =\n%s", raw)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
	}
}

func TestNewRunnerAppliesMatcherFeatureFlag(t *testing.T) {
	t.Setenv("SYSARMOR_TEST_MATCHER_STRATEGY", "optimized")
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	runner, err := NewRunner(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "local"},
		Local:   config.LocalConfig{StatePath: t.TempDir()},
		Runtime: config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:  config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if got := matcher.DefaultStrategy(); got != matcher.StrategyOptimized {
		t.Fatalf("matcher strategy = %q, want optimized", got)
	}
}

func TestLearningDetectorFromConfigLoadsCollectedBundle(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsignedPath := filepath.Join("..", "..", "..", "..", "test", "data", "learning", "model-bundle.json")
	raw, err := os.ReadFile(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := detectionadapter.SignModelBundle(raw, "release-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTestFile(t, t.TempDir(), "model.json", string(signed))
	trustKeys := "release-test=" + base64.StdEncoding.EncodeToString(publicKey)
	detector, err := learningDetectorFromConfig(config.Config{Learning: config.LearningConfig{ModelPath: path, TrustKeys: trustKeys}})
	if err != nil {
		t.Fatal(err)
	}
	if detector == nil {
		t.Fatal("learning detector = nil")
	}
}

func TestLearningDetectorFromConfigReportsInvalidBundle(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "model.json", `{"model_ref":"model:bad"}`)
	if _, err := learningDetectorFromConfig(config.Config{Learning: config.LearningConfig{ModelPath: path}}); err == nil {
		t.Fatal("learningDetectorFromConfig() error = nil")
	}
}

func TestNewRunnerKeepsCoreRuntimeWhenLearningBundleFails(t *testing.T) {
	path := writeTestFile(t, t.TempDir(), "model.json", `{"model_ref":"model:bad"}`)
	runner, err := NewRunner(t.Context(), config.Config{
		Manager:  config.ManagerConfig{Transport: "local"},
		Local:    config.LocalConfig{StatePath: t.TempDir()},
		Sensor:   config.SensorConfig{Backend: "fake"},
		Learning: config.LearningConfig{ModelPath: path},
	})
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	defer runner.Close()
}

func TestNewRunnerRejectsMissingDefaultContentManifest(t *testing.T) {
	matcher.SetDefaultStrategy(matcher.StrategyOptimized)
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	_, err := NewRunner(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "local"},
		Runtime: config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:  config.SensorConfig{Backend: "fake"},
		Content: config.ContentConfig{DefaultPath: t.TempDir(), Path: t.TempDir()},
	})
	if err == nil || !strings.Contains(err.Error(), "default content manifest") {
		t.Fatalf("NewRunner() error = %v, want default content manifest error", err)
	}
	if got := matcher.DefaultStrategy(); got != matcher.StrategyOptimized {
		t.Fatalf("failed NewRunner changed matcher strategy to %q", got)
	}
}

func TestNewRunnerOwnsStandaloneLocalState(t *testing.T) {
	runner, err := NewRunner(t.Context(), config.Config{
		Local:  config.LocalConfig{StatePath: t.TempDir()},
		Sensor: config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.store == nil {
		t.Fatal("standalone local store = nil")
	}
	identity := runner.runtime.Config.Agent
	if identity.ID == "" || identity.HostID == "" || identity.TenantID != "local" {
		t.Fatalf("standalone identity = %+v", identity)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestNewRunnerOwnsManagedLocalState(t *testing.T) {
	runner, err := NewRunner(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "grpc"},
		Local:   config.LocalConfig{StatePath: t.TempDir()},
		Sensor:  config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if runner.store == nil {
		t.Fatal("managed local store = nil")
	}
}

func TestTetragonRestartPolicyFromConfig(t *testing.T) {
	policy, err := tetragonRestartPolicy(config.SensorConfig{Restart: "always", MaxRestarts: 7, RestartWindow: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if policy != (tetragon.ProcessRestartPolicy{Enabled: true, MaxRestarts: 7, Delay: 25 * time.Millisecond}) {
		t.Fatalf("policy = %+v", policy)
	}
	disabled, err := tetragonRestartPolicy(config.SensorConfig{Restart: "never"})
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled policy = %+v, error = %v", disabled, err)
	}
	if _, err := tetragonRestartPolicy(config.SensorConfig{Restart: "sometimes"}); err == nil {
		t.Fatal("tetragonRestartPolicy(unknown) error = nil")
	}
}

func TestSignContentProducesVerifiableEnvelope(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := writeTestFile(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	inputPath := writeTestFile(t, dir, "input.json", `{"api_version":"sysarmor.content/v1","kind":"contextset","metadata":{"id":"ctx:test","version":"v1"},"spec":{"value_type":"string","values":["value"]}}`)
	outputPath := filepath.Join(dir, "output.json")

	if err := SignContent(ContentSignOptions{KeyPath: keyPath, KeyID: "release-test", InputPath: inputPath, OutputPath: outputPath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := agentcontent.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	store, err := agentcontent.NewStoreWithOptions(agentcontent.Options{TrustedKeys: map[string]ed25519.PublicKey{"release-test": publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Validate(envelope, false); err != nil {
		t.Fatalf("signed content validation failed: %v", err)
	}
}

func TestSignLearningModelProducesVerifiableBundle(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := writeTestFile(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	inputPath := filepath.Join("..", "..", "..", "..", "test", "data", "learning", "model-bundle.json")
	outputPath := filepath.Join(dir, "signed-model.json")

	if err := SignLearningModel(ModelSignOptions{KeyPath: keyPath, KeyID: "release-test", InputPath: inputPath, OutputPath: outputPath}); err != nil {
		t.Fatal(err)
	}
	detector, err := detectionadapter.LoadModelBundle(outputPath, map[string]ed25519.PublicKey{"release-test": publicKey})
	if err != nil || detector == nil {
		t.Fatalf("signed model load = %v, error = %v", detector, err)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
