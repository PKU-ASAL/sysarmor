package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type RetryOptions struct {
	Initial time.Duration
	Max     time.Duration
}

type SupervisorStatus struct {
	State        string
	Running      bool
	LastError    string
	RestartCount uint64
}

type CollectionRuntime interface {
	Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error)
	Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error)
}

type ManagerCollectionRuntime struct {
	manager *Manager
}

func AdaptManager(manager *Manager) CollectionRuntime {
	return ManagerCollectionRuntime{manager: manager}
}

func (r ManagerCollectionRuntime) Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	return r.manager.Apply(ctx, intent)
}

func (r ManagerCollectionRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return r.manager.Subscribe(ctx)
}

type SubscriptionSupervisor struct {
	runtime   CollectionRuntime
	mu        sync.RWMutex
	intent    contract.CollectionIntent
	retry     RetryOptions
	events    chan contract.EventEnvelope
	updates   chan struct{}
	status    SupervisorStatus
	onApplied func(context.Context, contract.CollectionIntent) error
	revision  uint64
	waiters   map[uint64][]chan error
	manual    map[uint64]bool
}

type forwardResult uint8

const (
	forwardStopped forwardResult = iota
	forwardStreamClosed
	forwardIntentUpdated
)

func NewSubscriptionSupervisor(runtime CollectionRuntime, intent contract.CollectionIntent, retry RetryOptions) *SubscriptionSupervisor {
	if retry.Initial <= 0 {
		retry.Initial = time.Second
	}
	if retry.Max < retry.Initial {
		retry.Max = retry.Initial
	}
	return &SubscriptionSupervisor{runtime: runtime, intent: intent, retry: retry, events: make(chan contract.EventEnvelope), updates: make(chan struct{}, 1), status: SupervisorStatus{State: "starting"}, revision: 1, waiters: map[uint64][]chan error{}, manual: map[uint64]bool{}}
}

func (s *SubscriptionSupervisor) Events() <-chan contract.EventEnvelope { return s.events }

func (s *SubscriptionSupervisor) UpdateIntent(intent contract.CollectionIntent) {
	s.mu.Lock()
	s.intent = intent
	s.revision++
	s.mu.Unlock()
	s.signalUpdate()
}

func (s *SubscriptionSupervisor) Reconcile(ctx context.Context, intent contract.CollectionIntent) error {
	done := make(chan error, 1)
	s.mu.Lock()
	s.intent = intent
	s.revision++
	revision := s.revision
	s.waiters[revision] = append(s.waiters[revision], done)
	s.manual[revision] = true
	s.mu.Unlock()
	s.signalUpdate()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SubscriptionSupervisor) signalUpdate() {
	select {
	case s.updates <- struct{}{}:
	default:
	}
}

func (s *SubscriptionSupervisor) OnApplied(callback func(context.Context, contract.CollectionIntent) error) {
	s.mu.Lock()
	s.onApplied = callback
	s.mu.Unlock()
}

func (s *SubscriptionSupervisor) notifyApplied(ctx context.Context, intent contract.CollectionIntent) error {
	s.mu.RLock()
	callback := s.onApplied
	s.mu.RUnlock()
	if callback != nil {
		return callback(ctx, intent)
	}
	return nil
}

func (s *SubscriptionSupervisor) Status() SupervisorStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *SubscriptionSupervisor) markDegraded(stage string, err error) {
	s.mu.Lock()
	s.status.State = "degraded"
	s.status.Running = false
	s.status.LastError = fmt.Sprintf("%s: %v", stage, err)
	s.mu.Unlock()
}

func (s *SubscriptionSupervisor) markRunning() {
	s.mu.Lock()
	if s.status.State == "degraded" {
		s.status.RestartCount++
	}
	s.status.State = "running"
	s.status.Running = true
	s.status.LastError = ""
	s.mu.Unlock()
}

func (s *SubscriptionSupervisor) currentIntent() (contract.CollectionIntent, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.intent, s.revision
}

func (s *SubscriptionSupervisor) resolve(revision uint64, err error) {
	s.mu.Lock()
	waiters := s.waiters[revision]
	delete(s.waiters, revision)
	if err != nil {
		delete(s.manual, revision)
	}
	s.mu.Unlock()
	for _, waiter := range waiters {
		waiter <- err
	}
}

func (s *SubscriptionSupervisor) shouldNotify(revision uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	manual := s.manual[revision]
	delete(s.manual, revision)
	return !manual
}

func (s *SubscriptionSupervisor) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *SubscriptionSupervisor) run(ctx context.Context) {
	defer close(s.events)
	backoff := s.retry.Initial
	for {
		intent, revision := s.currentIntent()
		if _, err := s.runtime.Apply(ctx, intent); err != nil {
			s.resolve(revision, err)
			s.markDegraded("apply", err)
			if !s.wait(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, s.retry.Max)
			continue
		}
		subscribeCtx, cancelSubscribe := context.WithCancel(ctx)
		stream, err := s.runtime.Subscribe(subscribeCtx, intent)
		if err != nil || stream == nil {
			cancelSubscribe()
			if err == nil {
				err = fmt.Errorf("event stream is nil")
			}
			s.markDegraded("subscribe", err)
			s.resolve(revision, err)
			if !s.wait(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, s.retry.Max)
			continue
		}
		_, currentRevision := s.currentIntent()
		if currentRevision != revision {
			cancelSubscribe()
			if !waitStreamClosed(ctx, stream) {
				return
			}
			continue
		}
		if s.shouldNotify(revision) {
			if err := s.notifyApplied(ctx, intent); err != nil {
				cancelSubscribe()
				if !waitStreamClosed(ctx, stream) {
					return
				}
				s.markDegraded("reconcile", err)
				s.resolve(revision, err)
				if !s.wait(ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff, s.retry.Max)
				continue
			}
		}
		s.markRunning()
		s.resolve(revision, nil)
		backoff = s.retry.Initial
		forwardResult := s.forward(ctx, stream, revision)
		cancelSubscribe()
		if forwardResult == forwardIntentUpdated && !waitStreamClosed(ctx, stream) {
			return
		}
		switch forwardResult {
		case forwardStopped:
			return
		case forwardIntentUpdated:
			backoff = s.retry.Initial
			continue
		}
		s.markDegraded("subscribe", fmt.Errorf("event stream closed"))
		if !s.wait(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, s.retry.Max)
	}
}

func waitStreamClosed(ctx context.Context, stream <-chan contract.EventEnvelope) bool {
	for {
		select {
		case _, ok := <-stream:
			if !ok {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
}

func (s *SubscriptionSupervisor) forward(ctx context.Context, stream <-chan contract.EventEnvelope, revision uint64) forwardResult {
	for {
		select {
		case <-ctx.Done():
			return forwardStopped
		case <-s.updates:
			_, currentRevision := s.currentIntent()
			if currentRevision > revision {
				return forwardIntentUpdated
			}
		case event, ok := <-stream:
			if !ok {
				return forwardStreamClosed
			}
			select {
			case s.events <- event:
			case <-ctx.Done():
				return forwardStopped
			case <-s.updates:
				return forwardIntentUpdated
			}
		}
	}
}

func (s *SubscriptionSupervisor) wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	if current >= max/2 {
		return max
	}
	return current * 2
}
