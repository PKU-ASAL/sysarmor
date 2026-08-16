package health

import (
	"context"
	"time"

	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Service struct {
	source ports.HealthSource
	now    func() time.Time
}

func NewService(source ports.HealthSource) *Service {
	return &Service{source: source, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Snapshot(ctx context.Context) domainhealth.Snapshot {
	now := s.now()
	snapshot := domainhealth.Snapshot{ObservedAt: now}
	var err error
	snapshot.Runtime, err = s.source.Runtime(ctx)
	if err != nil {
		snapshot.Runtime.LastError = err.Error()
	}
	if !snapshot.StartedAt.IsZero() {
		snapshot.UptimeSeconds = int64(now.Sub(snapshot.StartedAt).Seconds())
	}
	snapshot.Sensor = s.sensor(ctx)
	snapshot.Telemetry = s.telemetry(ctx)
	snapshot.Telemetry.DroppedBatches = snapshot.Telemetry.Batcher.DroppedBatches
	snapshot.Telemetry.DroppedEvents = snapshot.Telemetry.Batcher.DroppedEvents
	snapshot.Telemetry.DroppedSignals = snapshot.Telemetry.Batcher.DroppedSignals
	if snapshot.Telemetry.LastError == "" {
		snapshot.Telemetry.LastError = firstError(snapshot.Telemetry.Batcher.LastError, snapshot.Telemetry.Sender.LastError)
	}
	snapshot.Detection = s.detection(ctx)
	snapshot.Detection.PendingPolicy = snapshot.PendingPolicy.Status != ""
	snapshot.Detection.EvictedGroups = snapshot.Detection.CEP.EvictedGroups
	snapshot.Detection.DroppedEventRefs = snapshot.Detection.CEP.DroppedEventRefs
	snapshot.Detection.EvalErrors = snapshot.Detection.CEP.EvalErrors
	snapshot.Storage = s.storage(ctx)
	snapshot.Lifecycle = s.lifecycle(ctx)
	snapshot.Status = domainhealth.Evaluate(snapshot)
	return snapshot
}

func firstError(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (s *Service) sensor(ctx context.Context) domainhealth.Sensor {
	value, err := s.source.Sensor(ctx)
	if err != nil {
		value.LastError = err.Error()
	}
	return value
}

func (s *Service) telemetry(ctx context.Context) domainhealth.Telemetry {
	value, err := s.source.Telemetry(ctx)
	if err != nil {
		value.LastError = err.Error()
	}
	return value
}

func (s *Service) detection(ctx context.Context) domainhealth.Detection {
	value, err := s.source.Detection(ctx)
	if err != nil {
		value.LastError = err.Error()
	}
	return value
}

func (s *Service) storage(ctx context.Context) domainhealth.Storage {
	value, err := s.source.Storage(ctx)
	if err != nil {
		value.LastError = err.Error()
	}
	return value
}

func (s *Service) lifecycle(ctx context.Context) domainhealth.Lifecycle {
	value, err := s.source.Lifecycle(ctx)
	if err != nil {
		value.LastError = err.Error()
	}
	return value
}
