package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestAgentRuntimeAppliesMatcherFeatureFlag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SYSARMOR_TEST_MATCHER_STRATEGY", "")
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Runtime:   config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "optimized"}},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: filepath.Join(dir, "collection.yaml"), ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
	}
	if err := os.WriteFile(cfg.Sensor.PolicyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := matcher.DefaultStrategy(); got != matcher.StrategyOptimized {
		t.Fatalf("matcher strategy = %q, want optimized", got)
	}
	if got := runner.detectionHealth().FeatureFlags.MatcherStrategy; got != "optimized" {
		t.Fatalf("health matcher strategy = %q, want optimized", got)
	}
}

func TestAgentRuntimeRejectsMissingDefaultContentManifest(t *testing.T) {
	cfg := config.Config{
		Manager: config.ManagerConfig{Address: "local", Transport: "local"},
		Runtime: config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:  config.SensorConfig{Backend: "fake", Mode: "managed", ObserveOnly: true},
		Content: config.ContentConfig{DefaultPath: t.TempDir(), Path: t.TempDir()},
	}
	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "default content manifest") {
		t.Fatalf("New() error = %v, want default content manifest error", err)
	}
}

func TestAgentRuntimeRejectsStartupDetectionWithoutRuleSet(t *testing.T) {
	runner := &AgentRuntime{content: agentcontent.NewStore()}
	err := runner.applyStartupDetection(policymodel.DefaultPolicy("default"))
	if err == nil || !strings.Contains(err.Error(), "explicit ruleset") {
		t.Fatalf("applyStartupDetection() error = %v, want explicit ruleset error", err)
	}
}

func TestDetectionStatusIncludesDefaultManifestVersion(t *testing.T) {
	runner := &AgentRuntime{}
	policy := policymodel.DefaultPolicy("default")
	policy.Detection = &policymodel.DetectionPolicy{PolicyID: "detection-test"}
	runner.setDetectionStatus(policy, detection.ApplyReport{Status: "applied"}, agentcontent.Snapshot{DefaultManifestVersion: "release-v1"})
	if got := runner.detectionHealth().DefaultManifestVersion; got != "release-v1" {
		t.Fatalf("detection manifest version = %q, want release-v1", got)
	}
}

func TestAgentRuntimeMatcherFeatureFlagTestOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SYSARMOR_TEST_MATCHER_STRATEGY", "optimized")
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Runtime:   config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: filepath.Join(dir, "collection.yaml"), ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
	}
	if err := os.WriteFile(cfg.Sensor.PolicyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := matcher.DefaultStrategy(); got != matcher.StrategyOptimized {
		t.Fatalf("matcher strategy = %q, want optimized", got)
	}
	if got := runner.detectionHealth().FeatureFlags.MatcherStrategy; got != "optimized" {
		t.Fatalf("health matcher strategy = %q, want optimized", got)
	}
}

func TestAgentRuntimeRejectsInvalidMatcherFeatureFlagOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SYSARMOR_TEST_MATCHER_STRATEGY", "auto")
	t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Runtime:   config.RuntimeConfig{FeatureFlags: config.RuntimeFeatureFlags{MatcherStrategy: "linear"}},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: filepath.Join(dir, "collection.yaml"), ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
	}
	if err := os.WriteFile(cfg.Sensor.PolicyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "matcher_strategy") {
		t.Fatalf("New() error = %v, want matcher strategy validation error", err)
	}
}
