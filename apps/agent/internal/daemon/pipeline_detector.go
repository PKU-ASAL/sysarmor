package daemon

import (
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

type runtimeDetector struct{ runner *AgentRuntime }

func (detector *runtimeDetector) Process(event domainevent.Event) []*domaindetection.Signal {
	if detector == nil || detector.runner == nil || detector.runner.currentDetection() == nil {
		return nil
	}
	return detector.runner.currentDetection().Process(event)
}
