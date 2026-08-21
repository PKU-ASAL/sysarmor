package pipeline

import (
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type DetectorSet struct {
	detectors []ports.EventDetector
}

func NewDetectorSet(detectors ...ports.EventDetector) *DetectorSet {
	set := &DetectorSet{detectors: make([]ports.EventDetector, 0, len(detectors))}
	for _, detector := range detectors {
		if detector != nil {
			set.detectors = append(set.detectors, detector)
		}
	}
	return set
}

func (set *DetectorSet) Process(event domainevent.Event) []*domaindetection.Signal {
	if set == nil {
		return nil
	}
	var signals []*domaindetection.Signal
	for _, detector := range set.detectors {
		signals = append(signals, detector.Process(event)...)
	}
	return signals
}
