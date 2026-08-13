package pipeline

import (
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestProcessMergesPolicyLabelsBeforeDetection(t *testing.T) {
	detector := &detectorFake{signals: []*domaindetection.Signal{{ID: "signal-a"}}}
	service := New(detector)
	original := domainevent.Event{ID: "event-a", Labels: map[string]string{"scenario": "test", "policy_id": "old"}}

	result, err := service.Process(original, map[string]string{"policy_id": "policy-a", "policy_version": "7"})
	if err != nil {
		t.Fatal(err)
	}
	if detector.event.Labels["policy_id"] != "policy-a" || detector.event.Labels["scenario"] != "test" {
		t.Fatalf("detector labels = %+v", detector.event.Labels)
	}
	if result.Event.Labels["policy_version"] != "7" || len(result.Signals) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if original.Labels["policy_id"] != "old" || len(original.Labels) != 2 {
		t.Fatalf("input labels mutated = %+v", original.Labels)
	}
}

func TestProcessRejectsMissingDetector(t *testing.T) {
	if _, err := New(nil).Process(domainevent.Event{}, nil); err == nil {
		t.Fatal("Process() error = nil")
	}
}

type detectorFake struct {
	event   domainevent.Event
	signals []*domaindetection.Signal
}

func (detector *detectorFake) Process(event domainevent.Event) []*domaindetection.Signal {
	detector.event = event
	return detector.signals
}
