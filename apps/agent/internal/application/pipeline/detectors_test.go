package pipeline

import (
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestDetectorSetPreservesDetectorAndSignalOrder(t *testing.T) {
	first := &detectorFake{signals: []*domaindetection.Signal{{ID: "rule-a"}, {ID: "rule-b"}}}
	second := &detectorFake{signals: []*domaindetection.Signal{{ID: "model-a"}}}

	signals := NewDetectorSet(first, second).Process(domainevent.Event{ID: "event-a"})

	if len(signals) != 3 || signals[0].ID != "rule-a" || signals[1].ID != "rule-b" || signals[2].ID != "model-a" {
		t.Fatalf("signals = %+v", signals)
	}
	if first.event.ID != "event-a" || second.event.ID != "event-a" {
		t.Fatalf("detector events = %+v, %+v", first.event, second.event)
	}
}

func TestDetectorSetIgnoresUnconfiguredOptionalDetector(t *testing.T) {
	rule := &detectorFake{signals: []*domaindetection.Signal{{ID: "rule-a"}}}

	signals := NewDetectorSet(rule, nil).Process(domainevent.Event{ID: "event-a"})

	if len(signals) != 1 || signals[0].ID != "rule-a" {
		t.Fatalf("signals = %+v", signals)
	}
}
