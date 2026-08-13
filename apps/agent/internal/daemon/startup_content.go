package daemon

import (
	"fmt"
	"strings"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func newContentStore(cfg config.Config) (*agentcontent.Store, error) {
	options := agentcontent.Options{
		DefaultDir:  cfg.Content.DefaultPath,
		Dir:         cfg.Content.Path,
		TrustedKeys: parseTrustKeys(cfg.Content.TrustKeys),
	}
	if strings.TrimSpace(options.DefaultDir) != "" {
		return agentcontent.OpenLayered(options)
	}
	return agentcontent.NewStoreWithOptions(options)
}

func (r *AgentRuntime) applyStartupDetection(policy policymodel.Policy) error {
	policy = policymodel.Normalize(policy)
	engine, report := detection.NewWithRuntimeLimits(
		policy.Detection, r.currentCollectionIntent(), r.detectionContentSnapshot(), r.detectionLimits(),
	)
	if report.Status == "rejected" {
		r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
		return fmt.Errorf("%s: %s", report.Message, strings.Join(report.Details, "; "))
	}
	r.setPolicy(policy)
	r.setDetection(engine)
	r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
	return nil
}
