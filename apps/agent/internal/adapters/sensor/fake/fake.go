package fake

import (
	"context"
	"sync"
	"time"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Sensor struct {
	mu            sync.Mutex
	intent        contract.CollectionIntent
	policyLoaded  bool
	eventsSeen    uint64
	lastEventAt   time.Time
	startupEvents []contract.EventEnvelope
}

func New() *Sensor {
	return NewWithStartupEvents(1)
}

func NewWithStartupEvents(count int) *Sensor {
	if count < 0 {
		count = 0
	}
	events := make([]contract.EventEnvelope, 0, count)
	now := time.Now().UnixNano()
	for i := 0; i < count; i++ {
		events = append(events, contract.EventEnvelope{
			SensorEvent: &sensorv1.SensorEvent{
				Behavior: domainevent.BehaviorProcessExec,
				Proc:     &sensorv1.RawProcess{Pid: uint32(i + 1), Binary: "/usr/bin/fake", StartTimeNs: uint64(now + int64(i))},
			},
			RawRef: "fake-startup",
		})
	}
	return &Sensor{
		startupEvents: events,
	}
}

func (s *Sensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{
		Backend:         "fake",
		Version:         "dev",
		SupportsExec:    true,
		SupportsConnect: true,
		SupportsFile:    true,
		SupportsHealth:  true,
	}, nil
}

func (s *Sensor) Apply(_ context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intent = intent
	s.policyLoaded = true
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *Sensor) Subscribe(ctx context.Context, intent contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	s.mu.Lock()
	if !s.policyLoaded {
		s.intent = intent
		s.policyLoaded = true
	}
	events := append([]contract.EventEnvelope(nil), s.startupEvents...)
	s.mu.Unlock()

	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		for _, ev := range events {
			if ev.ReceivedAt.IsZero() {
				ev.ReceivedAt = time.Now().UTC()
			}
			select {
			case <-ctx.Done():
				return
			case out <- ev:
				s.mu.Lock()
				s.eventsSeen++
				s.lastEventAt = ev.ReceivedAt
				s.mu.Unlock()
			}
		}
		<-ctx.Done()
	}()
	return out, nil
}

func (s *Sensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "fake sensor is observe-only"), nil
}

func (s *Sensor) Health(context.Context) (contract.Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return contract.Health{
		Backend:      "fake",
		Running:      true,
		Installed:    true,
		Version:      "dev",
		PolicyLoaded: s.policyLoaded,
		EventsSeen:   s.eventsSeen,
		LastEventAt:  s.lastEventAt,
	}, nil
}
