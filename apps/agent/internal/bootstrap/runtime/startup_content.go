package runtime

import (
	"fmt"
	"strings"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func (r *Runtime) applyStartupDetection(policy policymodel.Policy) error {
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
