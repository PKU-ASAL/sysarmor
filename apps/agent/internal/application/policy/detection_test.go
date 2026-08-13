package policy

import (
	"context"
	"errors"
	"testing"
)

type detectionCandidateFake struct {
	id     string
	report DetectionReport
}

func (c detectionCandidateFake) PolicyID() string             { return c.id }
func (c detectionCandidateFake) PolicyVersion() uint64        { return 2 }
func (c detectionCandidateFake) BuildReport() DetectionReport { return c.report }

type detectionRepoFake struct {
	candidate  DetectionCandidate
	persistErr error
	events     *[]string
}

func (f *detectionRepoFake) PrepareDetection(context.Context, string) (DetectionCandidate, error) {
	return f.candidate, nil
}
func (f *detectionRepoFake) PersistDetection(context.Context, DetectionCandidate) error {
	*f.events = append(*f.events, "persist")
	return f.persistErr
}

type detectionRuntimeFake struct{ events *[]string }

func (f *detectionRuntimeFake) RecordRejectedDetection(DetectionCandidate) {
	*f.events = append(*f.events, "reject")
}
func (f *detectionRuntimeFake) PublishDetection(DetectionCandidate) {
	*f.events = append(*f.events, "publish")
}

func TestDetectionPersistsBeforePublish(t *testing.T) {
	events := []string{}
	c := detectionCandidateFake{id: "d1", report: DetectionReport{Status: "applied"}}
	s := NewDetectionService(&detectionRepoFake{candidate: c, events: &events}, &detectionRuntimeFake{events: &events})
	if _, err := s.Activate(t.Context(), "{}"); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0] != "persist" || events[1] != "publish" {
		t.Fatalf("events=%v", events)
	}
}

func TestDetectionRejectedBuildOnlyRecordsStatus(t *testing.T) {
	events := []string{}
	c := detectionCandidateFake{id: "d1", report: DetectionReport{Status: "rejected"}}
	s := NewDetectionService(&detectionRepoFake{candidate: c, events: &events}, &detectionRuntimeFake{events: &events})
	r, err := s.Activate(t.Context(), "{}")
	if err != nil || r.Report.Status != "rejected" || len(events) != 1 || events[0] != "reject" {
		t.Fatalf("result=%+v events=%v err=%v", r, events, err)
	}
}

func TestDetectionPersistenceFailureDoesNotPublish(t *testing.T) {
	events := []string{}
	c := detectionCandidateFake{id: "d1", report: DetectionReport{Status: "applied"}}
	s := NewDetectionService(&detectionRepoFake{candidate: c, persistErr: errors.New("disk full"), events: &events}, &detectionRuntimeFake{events: &events})
	if _, err := s.Activate(t.Context(), "{}"); err == nil {
		t.Fatal("expected error")
	}
	if len(events) != 1 {
		t.Fatalf("events=%v", events)
	}
}
