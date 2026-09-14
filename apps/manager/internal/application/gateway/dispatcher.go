package gateway

import (
	"context"
	"fmt"
	"sync"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Dispatcher struct {
	mu        sync.Mutex
	handlers  map[string]ports.ControlHandler
	sequences map[string]uint64
}

func NewDispatcher(handlers map[string]ports.ControlHandler) *Dispatcher {
	copy := make(map[string]ports.ControlHandler, len(handlers))
	for kind, handler := range handlers {
		copy[kind] = handler
	}
	return &Dispatcher{handlers: copy, sequences: map[string]uint64{}}
}

func (dispatcher *Dispatcher) Dispatch(ctx context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
	handler := dispatcher.handlers[frame.Type]
	if handler == nil {
		return ports.ControlResult{}, fmt.Errorf("unknown control frame type %q", frame.Type)
	}
	if err := dispatcher.acceptSequence(frame); err != nil {
		return ports.ControlResult{}, err
	}
	return handler.Handle(ctx, frame)
}

func (dispatcher *Dispatcher) acceptSequence(frame ports.ControlFrame) error {
	if frame.SessionID == "" || frame.Sequence == 0 {
		return fmt.Errorf("control session and sequence are required")
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	last := dispatcher.sequences[frame.SessionID]
	if frame.Sequence <= last {
		return fmt.Errorf("control frame replay: sequence=%d last=%d", frame.Sequence, last)
	}
	if last > 0 && frame.Sequence != last+1 {
		return fmt.Errorf("control frame sequence gap: sequence=%d want=%d", frame.Sequence, last+1)
	}
	dispatcher.sequences[frame.SessionID] = frame.Sequence
	return nil
}
