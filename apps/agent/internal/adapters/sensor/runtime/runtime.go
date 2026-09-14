package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Runtime interface {
	Probe(ctx context.Context) (contract.Capability, error)
	Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error)
	Subscribe(ctx context.Context) (<-chan contract.EventEnvelope, error)
	Enforce(ctx context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error)
	Health(ctx context.Context) (contract.Health, error)
	Stop(ctx context.Context) error
}

type Manager struct {
	sensor contract.Sensor

	mu         sync.Mutex
	intent     contract.CollectionIntent
	applied    bool
	cancel     context.CancelFunc
	eventsSeen atomic.Uint64
}

func New(sensor contract.Sensor) *Manager {
	return &Manager{sensor: sensor}
}

func (m *Manager) Probe(ctx context.Context) (contract.Capability, error) {
	if m.sensor == nil {
		return contract.Capability{}, fmt.Errorf("sensor is nil")
	}
	return m.sensor.Capability(ctx)
}

func (m *Manager) Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	if m.sensor == nil {
		return contract.ApplyResult{}, fmt.Errorf("sensor is nil")
	}
	normalized, err := intent.NormalizeScope()
	if err != nil {
		return contract.ApplyResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result, applyErr := m.sensor.Apply(ctx, normalized)
	if applyErr != nil {
		return contract.ApplyResult{}, applyErr
	}
	m.intent = normalized
	m.applied = true
	return result, nil
}

func (m *Manager) Subscribe(ctx context.Context) (<-chan contract.EventEnvelope, error) {
	if m.sensor == nil {
		return nil, fmt.Errorf("sensor is nil")
	}
	m.mu.Lock()
	if !m.applied {
		m.mu.Unlock()
		return nil, fmt.Errorf("collection intent has not been applied")
	}
	intent := m.intent
	subCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.mu.Unlock()

	in, err := m.sensor.Subscribe(subCtx, intent)
	if err != nil {
		cancel()
		return nil, err
	}
	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		for {
			select {
			case <-subCtx.Done():
				drainEventStream(in)
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				if ev.ReceivedAt.IsZero() {
					ev.ReceivedAt = time.Now().UTC()
				}
				m.eventsSeen.Add(1)
				select {
				case out <- ev:
				case <-subCtx.Done():
					drainEventStream(in)
					return
				}
			}
		}
	}()
	return out, nil
}

func drainEventStream(events <-chan contract.EventEnvelope) {
	for range events {
	}
}

func (m *Manager) Enforce(ctx context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	if m.sensor == nil {
		return contract.EnforcementAck{}, fmt.Errorf("sensor is nil")
	}
	return m.sensor.Enforce(ctx, cmd)
}

func (m *Manager) Health(ctx context.Context) (contract.Health, error) {
	if m.sensor == nil {
		return contract.Health{}, fmt.Errorf("sensor is nil")
	}
	health, err := m.sensor.Health(ctx)
	if err != nil {
		return contract.Health{}, err
	}
	if health.EventsSeen == 0 {
		health.EventsSeen = m.eventsSeen.Load()
	}
	return health, nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
