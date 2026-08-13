package daemon

import (
	"strings"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

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
