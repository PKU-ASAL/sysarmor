package daemon

import (
	"context"
	"reflect"
	"sync"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

type networkSupervisor struct {
	transitionMu    sync.Mutex
	mu              sync.Mutex
	parent          context.Context
	startStandalone func(context.Context)
	startManaged    func(context.Context, localstore.Enrollment)
	cancel          context.CancelFunc
	done            chan struct{}
	enrollment      localstore.Enrollment
	mode            management.Context
}

func newNetworkSupervisor(parent context.Context, startStandalone func(context.Context), startManaged func(context.Context, localstore.Enrollment)) *networkSupervisor {
	return &networkSupervisor{parent: parent, startStandalone: startStandalone, startManaged: startManaged}
}

func (s *networkSupervisor) ApplyEnrollment(enrollment localstore.Enrollment, mode management.Context) {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	s.mu.Lock()
	if s.cancel != nil && reflect.DeepEqual(s.enrollment, enrollment) && s.mode == mode {
		s.mu.Unlock()
		return
	}
	cancel, done := s.detachLocked()
	s.mu.Unlock()
	stopNetworkFlow(cancel, done)
	ctx, cancel := context.WithCancel(s.parent)
	done = make(chan struct{})
	s.mu.Lock()
	s.cancel = cancel
	s.done = done
	s.enrollment = enrollment
	s.mode = mode
	s.mu.Unlock()
	go s.run(ctx, enrollment, mode, done)
}

func (s *networkSupervisor) Stop() {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	s.mu.Lock()
	cancel, done := s.detachLocked()
	s.mu.Unlock()
	stopNetworkFlow(cancel, done)
}

func (s *networkSupervisor) PromoteEnrollment(enrollment localstore.Enrollment, mode management.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil || s.mode.State != management.StateEnrolling || mode.State != management.StateManaged ||
		s.mode.Transport != management.TransportManaged || mode.Transport != management.TransportManaged {
		return false
	}
	s.enrollment = enrollment
	s.mode = mode
	return true
}

func (s *networkSupervisor) Managed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel != nil && s.mode.Transport == management.TransportManaged
}

func (s *networkSupervisor) run(ctx context.Context, enrollment localstore.Enrollment, mode management.Context, done chan struct{}) {
	defer close(done)
	if mode.Transport == management.TransportStandalone {
		s.startStandalone(ctx)
		return
	}
	s.startManaged(ctx, enrollment)
}

func (s *networkSupervisor) detachLocked() (context.CancelFunc, chan struct{}) {
	cancel, done := s.cancel, s.done
	s.cancel = nil
	s.done = nil
	s.enrollment = localstore.Enrollment{}
	s.mode = management.Context{}
	return cancel, done
}

func stopNetworkFlow(cancel context.CancelFunc, done <-chan struct{}) {
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}
