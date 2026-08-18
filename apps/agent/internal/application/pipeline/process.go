package pipeline

import (
	"fmt"
	"strings"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Result struct {
	Event   domainevent.Event
	Signals []*domaindetection.Signal
}

type Service struct {
	rules    ports.EventDetector
	learning ports.ProfileDetector
	profiles *domainprocess.Profiles
}

func New(rules ports.EventDetector, learning ports.ProfileDetector, profiles *domainprocess.Profiles) *Service {
	return &Service{rules: rules, learning: learning, profiles: profiles}
}

func (service *Service) Process(event domainevent.Event, labels map[string]string) (Result, error) {
	if service == nil || service.rules == nil || service.profiles == nil {
		return Result{}, fmt.Errorf("event pipeline is not initialized")
	}
	event.Labels = mergeLabels(event.Labels, labels)
	signals := service.rules.Process(event)
	if event.Subject.StableID != "" {
		if service.learning == nil {
			service.profiles.Observe(event)
		} else if snapshot, ok := service.profiles.ObserveSnapshot(event); !ok {
			return Result{}, fmt.Errorf("process profile %q is not initialized", event.Subject.StableID)
		} else {
			signals = append(signals, service.learning.Process(snapshot)...)
		}
	}
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
