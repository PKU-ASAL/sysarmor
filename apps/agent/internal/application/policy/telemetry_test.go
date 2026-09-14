package policy

import (
	"context"
	"errors"
	"testing"
)

type telemetryCandidateFake struct{}

func (telemetryCandidateFake) ReportJSON() string { return `{}` }

type telemetryRepoFake struct {
	err    error
	events *[]string
}

func (*telemetryRepoFake) PrepareTelemetry(context.Context, string, *TelemetryInput) (TelemetryCandidate, error) {
	return telemetryCandidateFake{}, nil
}
func (f *telemetryRepoFake) PersistTelemetry(context.Context, TelemetryCandidate) error {
	*f.events = append(*f.events, "persist")
	return f.err
}

type telemetryRuntimeFake struct{ events *[]string }

func (f *telemetryRuntimeFake) PublishTelemetry(TelemetryCandidate) {
	*f.events = append(*f.events, "publish")
}

func TestTelemetryPersistsBeforePublish(t *testing.T) {
	events := []string{}
	s := NewTelemetryService(&telemetryRepoFake{events: &events}, &telemetryRuntimeFake{events: &events})
	if _, err := s.Activate(t.Context(), "{}", nil); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0] != "persist" || events[1] != "publish" {
		t.Fatalf("events=%v", events)
	}
}
func TestTelemetryPersistenceFailureDoesNotPublish(t *testing.T) {
	events := []string{}
	s := NewTelemetryService(&telemetryRepoFake{events: &events, err: errors.New("disk full")}, &telemetryRuntimeFake{events: &events})
	if _, err := s.Activate(t.Context(), "{}", nil); err == nil {
		t.Fatal("expected error")
	}
	if len(events) != 1 {
		t.Fatalf("events=%v", events)
	}
}
