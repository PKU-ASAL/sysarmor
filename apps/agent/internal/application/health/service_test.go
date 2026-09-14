package health

import (
	"context"
	"errors"
	"testing"
	"time"

	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
)

type source struct {
	runtime    domainhealth.Runtime
	sensor     domainhealth.Sensor
	telemetry  domainhealth.Telemetry
	detection  domainhealth.Detection
	storage    domainhealth.Storage
	lifecycle  domainhealth.Lifecycle
	sensorErr  error
	runtimeErr error
}

func (s source) Runtime(context.Context) (domainhealth.Runtime, error) {
	return s.runtime, s.runtimeErr
}
func (s source) Sensor(context.Context) (domainhealth.Sensor, error)       { return s.sensor, s.sensorErr }
func (s source) Telemetry(context.Context) (domainhealth.Telemetry, error) { return s.telemetry, nil }
func (s source) Detection(context.Context) (domainhealth.Detection, error) { return s.detection, nil }
func (s source) Storage(context.Context) (domainhealth.Storage, error)     { return s.storage, nil }
func (s source) Lifecycle(context.Context) (domainhealth.Lifecycle, error) { return s.lifecycle, nil }

func TestServiceAggregatesHealthyComponents(t *testing.T) {
	service := NewService(source{
		runtime: domainhealth.Runtime{AgentID: "agent-a", TenantID: "tenant-a", StartedAt: time.Now().Add(-time.Minute)},
		sensor:  domainhealth.Sensor{Running: true},
	})
	snapshot := service.Snapshot(t.Context())
	if snapshot.Status != domainhealth.StatusOK || snapshot.AgentID != "agent-a" || snapshot.UptimeSeconds < 59 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceSurfacesRuntimeSamplingFailureAsDegraded(t *testing.T) {
	service := NewService(source{sensor: domainhealth.Sensor{Running: true}, runtimeErr: errors.New("pending policy unavailable")})
	snapshot := service.Snapshot(t.Context())
	if snapshot.Status != domainhealth.StatusDegraded || snapshot.Runtime.LastError != "pending policy unavailable" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceIsolatesComponentFailureAsDegradedHealth(t *testing.T) {
	service := NewService(source{
		runtime:   domainhealth.Runtime{AgentID: "agent-a"},
		sensorErr: errors.New("sensor unavailable"),
	})
	snapshot := service.Snapshot(t.Context())
	if snapshot.Status != domainhealth.StatusDegraded || snapshot.Sensor.LastError != "sensor unavailable" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceDegradesForPendingPolicyDetectionAndLifecycle(t *testing.T) {
	service := NewService(source{
		runtime:   domainhealth.Runtime{PendingPolicy: domainhealth.PendingPolicy{Status: "pending"}},
		sensor:    domainhealth.Sensor{Running: true},
		detection: domainhealth.Detection{CEP: domainhealth.CEP{EvictedGroups: 1}},
		lifecycle: domainhealth.Lifecycle{TransitionPending: true},
	})
	if snapshot := service.Snapshot(t.Context()); snapshot.Status != domainhealth.StatusDegraded {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceDegradesForBatcherLoss(t *testing.T) {
	tests := []struct {
		name    string
		batcher domainhealth.Batcher
		assert  func(t *testing.T, telemetry domainhealth.Telemetry)
	}{
		{name: "batches", batcher: domainhealth.Batcher{DroppedBatches: 1}, assert: func(t *testing.T, telemetry domainhealth.Telemetry) {
			if telemetry.DroppedBatches != 1 {
				t.Fatalf("dropped batches=%d, want 1", telemetry.DroppedBatches)
			}
		}},
		{name: "events", batcher: domainhealth.Batcher{DroppedEvents: 1}, assert: func(t *testing.T, telemetry domainhealth.Telemetry) {
			if telemetry.DroppedEvents != 1 {
				t.Fatalf("dropped events=%d, want 1", telemetry.DroppedEvents)
			}
		}},
		{name: "signals", batcher: domainhealth.Batcher{DroppedSignals: 1}, assert: func(t *testing.T, telemetry domainhealth.Telemetry) {
			if telemetry.DroppedSignals != 1 {
				t.Fatalf("dropped signals=%d, want 1", telemetry.DroppedSignals)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := NewService(source{
				sensor:    domainhealth.Sensor{Running: true},
				telemetry: domainhealth.Telemetry{Batcher: test.batcher},
			}).Snapshot(t.Context())
			if snapshot.Status != domainhealth.StatusDegraded {
				t.Fatalf("status=%q, want degraded", snapshot.Status)
			}
			test.assert(t, snapshot.Telemetry)
		})
	}
}

func TestServiceDoesNotTreatStreamEvictionAsDataLoss(t *testing.T) {
	service := NewService(source{
		sensor: domainhealth.Sensor{Running: true},
		telemetry: domainhealth.Telemetry{
			Streams: domainhealth.Streams{EventEvicted: 1},
		},
	})
	if snapshot := service.Snapshot(t.Context()); snapshot.Status != domainhealth.StatusOK {
		t.Fatalf("status=%q, want ok: %+v", snapshot.Status, snapshot)
	}
}

func TestServiceUsesConfiguredSensorLossThresholds(t *testing.T) {
	service := NewService(source{sensor: domainhealth.Sensor{
		Running: true, EventsDropped: 2, ParseErrors: 2, MaxDroppedEvents: 2, MaxParseErrors: 2,
	}})
	if snapshot := service.Snapshot(t.Context()); snapshot.Status != domainhealth.StatusOK {
		t.Fatalf("status=%q, want ok", snapshot.Status)
	}
	service = NewService(source{sensor: domainhealth.Sensor{
		Running: true, EventsDropped: 3, ParseErrors: 2, MaxDroppedEvents: 2, MaxParseErrors: 2,
	}})
	if snapshot := service.Snapshot(t.Context()); snapshot.Status != domainhealth.StatusDegraded {
		t.Fatalf("status=%q, want degraded", snapshot.Status)
	}
}

func TestServiceDegradesForRejectedDetectionApply(t *testing.T) {
	service := NewService(source{
		sensor:    domainhealth.Sensor{Running: true},
		detection: domainhealth.Detection{LastApplyStatus: "rejected", LastApplyError: "invalid ruleset"},
	})
	if snapshot := service.Snapshot(t.Context()); snapshot.Status != domainhealth.StatusDegraded {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
