package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type controlHandlerFunc func(context.Context, ports.ControlFrame) (ports.ControlResult, error)

func (handler controlHandlerFunc) Handle(ctx context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
	return handler(ctx, frame)
}

func TestDispatcherRoutesKnownFrame(t *testing.T) {
	dispatcher := NewDispatcher(map[string]ports.ControlHandler{"hello": controlHandlerFunc(func(_ context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
		return ports.ControlResult{Frames: []ports.ControlFrame{frame}}, nil
	})})
	result, err := dispatcher.Dispatch(context.Background(), controlFrame("hello", 1))
	if err != nil || len(result.Frames) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
func TestDispatcherRejectsReplayAndGap(t *testing.T) {
	dispatcher := NewDispatcher(map[string]ports.ControlHandler{"health": controlHandlerFunc(func(context.Context, ports.ControlFrame) (ports.ControlResult, error) {
		return ports.ControlResult{}, nil
	})})
	if _, err := dispatcher.Dispatch(context.Background(), controlFrame("health", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := dispatcher.Dispatch(context.Background(), controlFrame("health", 1)); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay err=%v", err)
	}
	if _, err := dispatcher.Dispatch(context.Background(), controlFrame("health", 3)); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("gap err=%v", err)
	}
}
func TestDispatcherRejectsUnknownFrame(t *testing.T) {
	if _, err := NewDispatcher(nil).Dispatch(context.Background(), controlFrame("mystery", 1)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("err=%v", err)
	}
}
func controlFrame(kind string, sequence uint64) ports.ControlFrame {
	return ports.ControlFrame{SessionID: "session-a", Type: kind, Sequence: sequence}
}
