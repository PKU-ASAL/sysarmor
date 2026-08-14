package runtime

import (
	"context"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestManagerLifecycle(t *testing.T) {
	ctx := context.Background()
	fake := newFakeSensor()
	rt := New(fake)

	capability, err := rt.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if capability.Backend != "fake" || !capability.SupportsExec {
		t.Fatalf("unexpected capability: %+v", capability)
	}

	intent := contract.CollectionIntent{
		Behaviors:   []string{"process.exec"},
		ObserveOnly: true,
	}
	if _, err := rt.Apply(ctx, intent); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if fake.applied.ScopeType != "host" || fake.applied.ScopeSelector != "" {
		t.Fatalf("applied scope = %q/%q", fake.applied.ScopeType, fake.applied.ScopeSelector)
	}
	events, err := rt.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	fake.emit(contract.EventEnvelope{SensorEvent: &sensorv1.SensorEvent{Behavior: "process.exec"}})

	select {
	case ev := <-events:
		if ev.SensorEvent.GetBehavior() != "process.exec" {
			t.Fatalf("event behavior = %v", ev.SensorEvent.GetBehavior())
		}
		if ev.ReceivedAt.IsZero() {
			t.Fatal("ReceivedAt was not set")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}

	health, err := rt.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.EventsSeen != 1 {
		t.Fatalf("EventsSeen = %d", health.EventsSeen)
	}
	if err := rt.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestManagerRequiresApplyBeforeSubscribe(t *testing.T) {
	rt := New(newFakeSensor())
	if _, err := rt.Subscribe(context.Background()); err == nil {
		t.Fatal("Subscribe() error = nil")
	}
}

func TestManagerSubscriptionWaitsForSensorCleanup(t *testing.T) {
	sensor := &delayedCleanupSensor{
		fakeSensor:     newFakeSensor(),
		cleanupStarted: make(chan struct{}),
		releaseCleanup: make(chan struct{}),
	}
	rt := New(sensor)
	if _, err := rt.Apply(t.Context(), contract.CollectionIntent{}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	events, err := rt.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	cancel()
	<-sensor.cleanupStarted

	select {
	case <-events:
		t.Fatal("manager stream closed before sensor cleanup completed")
	default:
	}
	close(sensor.releaseCleanup)
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("manager stream emitted an event while closing")
		}
	case <-time.After(time.Second):
		t.Fatal("manager stream did not close after sensor cleanup")
	}
}

func TestManagerRejectsInvalidScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		intent   contract.CollectionIntent
		wantText string
	}{
		{
			name:     "invalid type",
			intent:   contract.CollectionIntent{ScopeType: "vm", ObserveOnly: true},
			wantText: "scope type must be one of",
		},
		{
			name:     "missing selector",
			intent:   contract.CollectionIntent{ScopeType: "container", ObserveOnly: true},
			wantText: "scope selector is required",
		},
		{
			name:     "host selector",
			intent:   contract.CollectionIntent{ScopeType: "host", ScopeSelector: "abc123", ObserveOnly: true},
			wantText: "scope selector must be empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeSensor()
			rt := New(fake)
			_, err := rt.Apply(context.Background(), tc.intent)
			if err == nil {
				t.Fatal("Apply() error = nil")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Apply() error = %v, want %q", err, tc.wantText)
			}
			if fake.applyCount != 0 {
				t.Fatalf("backend Apply called %d times", fake.applyCount)
			}
		})
	}
}

type fakeSensor struct {
	events     chan contract.EventEnvelope
	applied    contract.CollectionIntent
	applyCount int
}

type delayedCleanupSensor struct {
	*fakeSensor
	cleanupStarted chan struct{}
	releaseCleanup chan struct{}
}

func newFakeSensor() *fakeSensor {
	return &fakeSensor{events: make(chan contract.EventEnvelope, 1)}
}

func (f *fakeSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: "fake", Version: "test", SupportsExec: true, SupportsHealth: true}, nil
}

func (f *fakeSensor) Apply(_ context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	f.applied = intent
	f.applyCount++
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (f *fakeSensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-f.events:
				out <- ev
			}
		}
	}()
	return out, nil
}

func (s *delayedCleanupSensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	go func() {
		<-ctx.Done()
		close(s.cleanupStarted)
		<-s.releaseCleanup
		close(out)
	}()
	return out, nil
}

func (f *fakeSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "fake sensor is observe-only"), nil
}

func (f *fakeSensor) Health(context.Context) (contract.Health, error) {
	return contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}, nil
}

func (f *fakeSensor) emit(ev contract.EventEnvelope) {
	f.events <- ev
}
