package pipeline

import (
	"fmt"
	"strings"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Result struct {
	Event   domainevent.Event
	Signals []*domaindetection.Signal
}

type Service struct{ detector ports.EventDetector }

func New(detector ports.EventDetector) *Service {
	return &Service{detector: detector}
}

func (service *Service) Process(event domainevent.Event, labels map[string]string) (Result, error) {
	if service == nil || service.detector == nil {
		return Result{}, fmt.Errorf("event pipeline is not initialized")
	}
	event.Labels = mergeLabels(event.Labels, labels)
	signals := service.detector.Process(event)
	return Result{Event: event, Signals: append([]*domaindetection.Signal(nil), signals...)}, nil
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		if key = strings.TrimSpace(key); key != "" {
			out[key] = value
		}
	}
	for key, value := range extra {
		if key = strings.TrimSpace(key); key != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
