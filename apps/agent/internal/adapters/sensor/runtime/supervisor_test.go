package runtime

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestSubscriptionSupervisorRetriesApplyAndRecovers(t *testing.T) {
	rt := &flakyRuntime{applyFailures: 1}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, RetryOptions{
		Initial: time.Millisecond,
		Max:     2 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)

	select {
	case <-supervisor.Events():
		if atomic.LoadInt32(&rt.applyCalls) < 2 {
			t.Fatalf("apply calls = %d, want retry", rt.applyCalls)
		}
	case <-ctx.Done():
		t.Fatal("supervisor did not recover")
	}
}

func TestSubscriptionSupervisorReportsDegradedAndRecovery(t *testing.T) {
	rt := &controlledRuntime{apply: make(chan error, 2), stream: make(chan contract.EventEnvelope)}
	rt.apply <- errors.New("sensor unavailable")
	rt.apply <- nil
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: 20 * time.Millisecond, Max: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)

	waitForSupervisorState(t, supervisor, "degraded")
	waitForSupervisorState(t, supervisor, "running")
	status := supervisor.Status()
	if status.LastError != "" || !status.Running || status.RestartCount != 1 {
		t.Fatalf("recovered status = %+v", status)
	}
}

func waitForSupervisorState(t *testing.T, supervisor *SubscriptionSupervisor, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if supervisor.Status().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("supervisor state = %+v, want %s", supervisor.Status(), want)
}

func TestSubscriptionSupervisorRetriesNilStream(t *testing.T) {
	rt := &nilStreamRuntime{}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: time.Millisecond, Max: 2 * time.Millisecond})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)
	select {
	case <-supervisor.Events():
		if atomic.LoadInt32(&rt.subscribeCalls) < 2 {
			t.Fatalf("subscribe calls = %d, want retry", rt.subscribeCalls)
		}
	case <-ctx.Done():
		t.Fatal("supervisor did not retry nil stream")
	}
}

func TestSubscriptionSupervisorBacksOffAfterClosedStream(t *testing.T) {
	rt := &closedStreamRuntime{calls: make(chan time.Time, 2)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: 20 * time.Millisecond, Max: 40 * time.Millisecond})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)
	first := <-rt.calls
	second := <-rt.calls
	if elapsed := second.Sub(first); elapsed < 15*time.Millisecond {
		t.Fatalf("closed stream retry elapsed = %s, want bounded backoff", elapsed)
	}
}

func TestSubscriptionSupervisorReappliesLatestIntent(t *testing.T) {
	rt := &updatableRuntime{applied: make(chan contract.CollectionIntent, 2), stream: make(chan contract.EventEnvelope)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, RetryOptions{Initial: time.Millisecond, Max: 2 * time.Millisecond})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)
	<-rt.applied
	supervisor.UpdateIntent(contract.CollectionIntent{Behaviors: []string{"file.write"}})
	select {
	case latest := <-rt.applied:
		if len(latest.Behaviors) != 1 || latest.Behaviors[0] != "file.write" {
			t.Fatalf("reapplied intent = %+v", latest)
		}
	case <-ctx.Done():
		t.Fatal("intent update did not interrupt the active subscription")
	}
}

func TestSubscriptionSupervisorStopsPreviousStreamBeforeResubscribe(t *testing.T) {
	rt := &exclusiveRuntime{applied: make(chan contract.CollectionIntent, 2), subscribed: make(chan struct{}, 2)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)
	<-rt.subscribed
	supervisor.UpdateIntent(contract.CollectionIntent{Behaviors: []string{"file.write"}})
	select {
	case <-rt.subscribed:
	case <-ctx.Done():
		t.Fatal("intent update did not establish a replacement subscription")
	}
	if overlaps := atomic.LoadInt32(&rt.overlaps); overlaps != 0 {
		t.Fatalf("overlapping subscriptions = %d, want zero", overlaps)
	}
}

func TestSubscriptionSupervisorNotifiesSuccessfulApply(t *testing.T) {
	applied := make(chan contract.CollectionIntent, 1)
	rt := &intentRuntime{applied: make(chan contract.CollectionIntent, 1)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{Behaviors: []string{"process.exec"}}, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	supervisor.OnApplied(func(_ context.Context, intent contract.CollectionIntent) error { applied <- intent; return nil })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)
	select {
	case intent := <-applied:
		if len(intent.Behaviors) != 1 || intent.Behaviors[0] != "process.exec" {
			t.Fatalf("applied intent = %+v", intent)
		}
	case <-time.After(time.Second):
		t.Fatal("successful apply was not reported")
	}
}

func TestSubscriptionSupervisorReconcileAppliesIntentOnce(t *testing.T) {
	rt := &updatableRuntime{applied: make(chan contract.CollectionIntent, 2)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	supervisor.Start(ctx)
	select {
	case <-rt.applied:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not apply initial intent")
	}
	intent := contract.CollectionIntent{Behaviors: []string{"file.write"}}
	done := make(chan error, 1)
	go func() { done <- supervisor.Reconcile(ctx, intent) }()
	select {
	case got := <-rt.applied:
		if !reflect.DeepEqual(got, intent) {
			t.Fatalf("applied intent = %+v, want %+v", got, intent)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile did not apply intent")
	}
	if err := <-done; err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	select {
	case duplicate := <-rt.applied:
		t.Fatalf("reconcile applied duplicate intent: %+v", duplicate)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestSubscriptionSupervisorDoesNotNotifyAppliedWhenSubscribeFails(t *testing.T) {
	rt := &subscribeErrorRuntime{}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: time.Hour, Max: time.Hour})
	var callbacks atomic.Int32
	supervisor.OnApplied(func(context.Context, contract.CollectionIntent) error {
		callbacks.Add(1)
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)
	waitForSupervisorState(t, supervisor, "degraded")
	if callbacks.Load() != 0 {
		t.Fatalf("applied callbacks = %d, want zero after subscribe failure", callbacks.Load())
	}
}

func TestSubscriptionSupervisorSubscribesAfterDeferredApply(t *testing.T) {
	rt := &deferredApplyRuntime{}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	applied := make(chan struct{}, 1)
	supervisor.OnApplied(func(context.Context, contract.CollectionIntent) error {
		applied <- struct{}{}
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("deferred apply did not continue through successful subscribe")
	}
}

func TestSubscriptionSupervisorPassesLifecycleContextToAppliedCallback(t *testing.T) {
	rt := &intentRuntime{applied: make(chan contract.CollectionIntent, 1)}
	supervisor := NewSubscriptionSupervisor(rt, contract.CollectionIntent{}, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	callbackStopped := make(chan struct{})
	supervisor.OnApplied(func(ctx context.Context, _ contract.CollectionIntent) error {
		<-ctx.Done()
		close(callbackStopped)
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	supervisor.Start(ctx)
	<-rt.applied
	cancel()
	select {
	case <-callbackStopped:
	case <-time.After(time.Second):
		t.Fatal("applied callback did not receive lifecycle cancellation")
	}
}

func TestSubscriptionSupervisorDoesNotNotifySupersededRevision(t *testing.T) {
	rt := &supersededApplyRuntime{
		firstApplyStarted: make(chan struct{}),
		releaseFirstApply: make(chan struct{}),
	}
	initial := contract.CollectionIntent{Behaviors: []string{"process.exec"}}
	latest := contract.CollectionIntent{Behaviors: []string{"file.write"}}
	supervisor := NewSubscriptionSupervisor(rt, initial, RetryOptions{Initial: time.Millisecond, Max: time.Millisecond})
	notified := make(chan contract.CollectionIntent, 1)
	supervisor.OnApplied(func(_ context.Context, intent contract.CollectionIntent) error {
		notified <- intent
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	supervisor.Start(ctx)
	<-rt.firstApplyStarted

	done := make(chan error, 1)
	go func() { done <- supervisor.Reconcile(ctx, latest) }()
	waitForSupervisorRevision(t, supervisor, 2)
	close(rt.releaseFirstApply)

	if err := <-done; err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	select {
	case intent := <-notified:
		t.Fatalf("superseded revision notified as applied: %+v", intent)
	default:
	}
}

func waitForSupervisorRevision(t *testing.T, supervisor *SubscriptionSupervisor, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, revision := supervisor.currentIntent()
		if revision == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("supervisor revision did not reach %d", want)
}

type flakyRuntime struct {
	applyFailures int
	applyCalls    int32
}

type controlledRuntime struct {
	apply  chan error
	stream chan contract.EventEnvelope
}

func (r *controlledRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, <-r.apply
}
func (r *controlledRuntime) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return r.stream, nil
}

type nilStreamRuntime struct{ subscribeCalls int32 }

type closedStreamRuntime struct{ calls chan time.Time }

type subscribeErrorRuntime struct{}

type deferredApplyRuntime struct{}

type supersededApplyRuntime struct {
	firstApplyStarted chan struct{}
	releaseFirstApply chan struct{}
	applyCalls        atomic.Int32
}

type intentRuntime struct {
	applied chan contract.CollectionIntent
}

type updatableRuntime struct {
	applied chan contract.CollectionIntent
	stream  chan contract.EventEnvelope
}

type exclusiveRuntime struct {
	applied    chan contract.CollectionIntent
	subscribed chan struct{}
	active     int32
	overlaps   int32
}

func (r *exclusiveRuntime) Apply(_ context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	r.applied <- intent
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (r *exclusiveRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	if atomic.AddInt32(&r.active, 1) != 1 {
		atomic.AddInt32(&r.overlaps, 1)
	}
	stream := make(chan contract.EventEnvelope)
	r.subscribed <- struct{}{}
	go func() {
		<-ctx.Done()
		atomic.AddInt32(&r.active, -1)
		close(stream)
	}()
	return stream, nil
}

func (r *updatableRuntime) Apply(_ context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	r.applied <- intent
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (r *updatableRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	stream := make(chan contract.EventEnvelope)
	go func() {
		<-ctx.Done()
		close(stream)
	}()
	return stream, nil
}

func (r *intentRuntime) Apply(_ context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	r.applied <- intent
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}
func (r *intentRuntime) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	ch := make(chan contract.EventEnvelope)
	close(ch)
	return ch, nil
}

func (r *closedStreamRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}
func (r *closedStreamRuntime) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	r.calls <- time.Now()
	ch := make(chan contract.EventEnvelope)
	close(ch)
	return ch, nil
}

func (*subscribeErrorRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}
func (*subscribeErrorRuntime) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return nil, errors.New("sensor failed to start")
}

func (*deferredApplyRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateDeferred}, nil
}

func (r *supersededApplyRuntime) Apply(ctx context.Context, _ contract.CollectionIntent) (contract.ApplyResult, error) {
	if r.applyCalls.Add(1) == 1 {
		close(r.firstApplyStarted)
		select {
		case <-r.releaseFirstApply:
		case <-ctx.Done():
			return contract.ApplyResult{}, ctx.Err()
		}
	}
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (*supersededApplyRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	stream := make(chan contract.EventEnvelope)
	go func() {
		<-ctx.Done()
		close(stream)
	}()
	return stream, nil
}

func (*deferredApplyRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	stream := make(chan contract.EventEnvelope)
	go func() {
		<-ctx.Done()
		close(stream)
	}()
	return stream, nil
}

func (r *nilStreamRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}
func (r *nilStreamRuntime) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	if atomic.AddInt32(&r.subscribeCalls, 1) == 1 {
		return nil, nil
	}
	ch := make(chan contract.EventEnvelope, 1)
	ch <- contract.EventEnvelope{}
	close(ch)
	return ch, nil
}

func (r *flakyRuntime) Probe(context.Context) (contract.Capability, error) {
	return contract.Capability{}, nil
}

func (r *flakyRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	call := int(atomic.AddInt32(&r.applyCalls, 1))
	if call <= r.applyFailures {
		return contract.ApplyResult{}, errors.New("temporary sensor failure")
	}
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (r *flakyRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	ch := make(chan contract.EventEnvelope, 1)
	ch <- contract.EventEnvelope{}
	close(ch)
	return ch, nil
}

func (r *flakyRuntime) Enforce(context.Context, contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.EnforcementAck{}, nil
}

func (r *flakyRuntime) Health(context.Context) (contract.Health, error) {
	return contract.Health{}, nil
}

func (r *flakyRuntime) Stop(context.Context) error { return nil }
