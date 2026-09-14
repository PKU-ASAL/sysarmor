package runtime

import (
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

type runtimeDetector struct{ policy *policyRuntime }

func (detector *runtimeDetector) Process(event domainevent.Event) []*domaindetection.Signal {
	if detector == nil || detector.policy == nil || detector.policy.currentDetection() == nil {
		return nil
	}
	return detector.policy.currentDetection().Process(event)
}
