package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func newTestEventNormalizer(t testing.TB, runner *Coordinator, agentID, hostID string, options eventadapter.EventNormalizerOptions) *eventadapter.EventNormalizer {
	t.Helper()
	if runner.processProfiles == nil {
		profiles, err := domainprocess.NewProfiles(processProfileLimits(runner.Config))
		if err != nil {
			t.Fatal(err)
		}
		runner.processProfiles = profiles
	}
	return eventadapter.NewEventNormalizer(agentID, hostID, options, runner.processProfiles)
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

type eventSensor struct {
	events []contract.EventEnvelope
	ch     chan contract.EventEnvelope
	health contract.Health
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type capabilityErrorSensor struct {
	err error
}

func newStreamingEventSensor() *eventSensor {
	s := newEventSensor(nil)
	s.ch = make(chan contract.EventEnvelope, 16)
	return s
}

func (s *eventSensor) emit(ev contract.EventEnvelope) {
	s.ch <- ev
}

func newEventSensor(events []contract.EventEnvelope) *eventSensor {
	return &eventSensor{
		events: events,
		health: contract.Health{
			Backend:      "test",
			Installed:    true,
			Running:      true,
			Version:      "test",
			PolicyLoaded: true,
		},
	}
}

func (s *capabilityErrorSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{}, s.err
}

func (s *capabilityErrorSensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *capabilityErrorSensor) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return nil, nil
}

func (s *capabilityErrorSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *capabilityErrorSensor) Health(context.Context) (contract.Health, error) {
	return contract.Health{}, nil
}

func (s *healthOnlySensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: s.health.Backend, Version: "test", SupportsHealth: true}, nil
}

func (s *healthOnlySensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *healthOnlySensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		<-ctx.Done()
	}()
	return out, nil
}

func (s *healthOnlySensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *healthOnlySensor) Health(context.Context) (contract.Health, error) {
	return s.health, nil
}

func (s *eventSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: "test", Version: "test", SupportsExec: true, SupportsFile: true, SupportsHealth: true}, nil
}

func (s *eventSensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	s.health.PolicyLoaded = true
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *eventSensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	events := append([]contract.EventEnvelope(nil), s.events...)
	go func() {
		defer close(out)
		for _, ev := range events {
			select {
			case <-ctx.Done():
				return
			case out <- ev:
				s.health.EventsSeen++
				s.health.LastEventAt = time.Now().UTC()
			}
		}
		if s.ch == nil {
			<-ctx.Done()
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-s.ch:
				select {
				case <-ctx.Done():
					return
				case out <- ev:
					s.health.EventsSeen++
					s.health.LastEventAt = time.Now().UTC()
				}
			}
		}
	}()
	return out, nil
}

func (s *eventSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *eventSensor) Health(context.Context) (contract.Health, error) {
	return s.health, nil
}

func sensorEventEnvelope(behavior string, pid uint32, binary, filePath, dst string) contract.EventEnvelope {
	return contract.EventEnvelope{
		SensorEvent: &sensorv1.SensorEvent{
			Behavior: behavior,
			Proc: &sensorv1.RawProcess{
				Pid:         pid,
				Binary:      binary,
				StartTimeNs: uint64(time.Now().UnixNano()),
			},
			Object: &sensorv1.RawObject{
				Path: filePath,
				Dst:  dst,
			},
			RawRef: "test-policy-event",
		},
		RawRef: "test-policy-event",
	}
}

func runRuntimeUntilPersistedBatch(t *testing.T, runner *Coordinator, out *bytes.Buffer) *dataplanev1.DataBatch {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		opts := Options{}
		if out != nil {
			opts.Out = out
		}
		errCh <- runner.Run(ctx, opts)
	}()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			t.Fatalf("daemon exited before uploading a telemetry batch")
		case <-time.After(10 * time.Millisecond):
			batches, err := runner.managementState.localStore.ReadBatches(t.Context(), sqlite.ReadOptions{Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(batches) > 0 {
				cancel()
				if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("Run() error = %v", err)
				}
				return batches[0].Batch
			}
		case <-deadline:
			cancel()
			t.Fatalf("timed out waiting for persisted telemetry batch")
		}
	}
}

func runRuntimeUntilOutput(t *testing.T, runner *Coordinator, out interface {
	Write([]byte) (int, error)
	String() string
}, want string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, Options{Out: out})
	}()
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(out.String(), want) {
			cancel()
			if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			return
		}
		select {
		case err := <-errCh:
			if strings.Contains(out.String(), want) {
				return
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			t.Fatalf("daemon exited before output %q; got %q", want, out.String())
		case <-deadline:
			cancel()
			t.Fatalf("timed out waiting for output %q; got %q", want, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForOutput(t *testing.T, out interface{ String() string }, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(out.String(), want) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for output %q; got %q", want, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func testDataBatch(batchID, agentID, hostID string) *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{BatchId: batchID, AgentId: agentID, HostId: hostID, TenantId: "default"},
	}
}

func containsInt(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
