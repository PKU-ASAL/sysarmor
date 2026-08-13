package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
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

func TestNewAgentAppliesMatcherFeatureFlag(t *testing.T) {
	t.Setenv("SYSARMOR_TEST_MATCHER_STRATEGY", "optimized")
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	agent, err := NewAgent(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "local"},
		Runtime: config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:  config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if got := matcher.DefaultStrategy(); got != matcher.StrategyOptimized {
		t.Fatalf("matcher strategy = %q, want optimized", got)
	}
}

func TestNewAgentRejectsMissingDefaultContentManifest(t *testing.T) {
	_, err := NewAgent(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "local"},
		Runtime: config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:  config.SensorConfig{Backend: "fake"},
		Content: config.ContentConfig{DefaultPath: t.TempDir(), Path: t.TempDir()},
	})
	if err == nil || !strings.Contains(err.Error(), "default content manifest") {
		t.Fatalf("NewAgent() error = %v, want default content manifest error", err)
	}
}

func TestNewAgentOwnsStandaloneLocalState(t *testing.T) {
	agent, err := NewAgent(t.Context(), config.Config{
		Local:  config.LocalConfig{StatePath: t.TempDir()},
		Sensor: config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.store == nil {
		t.Fatal("standalone local store = nil")
	}
	identity := agent.runtime.Config.Agent
	if identity.ID == "" || identity.HostID == "" || identity.TenantID != "local" {
		t.Fatalf("standalone identity = %+v", identity)
	}
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewAgentDoesNotCreateManagedLocalState(t *testing.T) {
	agent, err := NewAgent(t.Context(), config.Config{
		Manager: config.ManagerConfig{Transport: "grpc"},
		Sensor:  config.SensorConfig{Backend: "fake"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.store != nil {
		t.Fatal("managed local store must be nil")
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

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
