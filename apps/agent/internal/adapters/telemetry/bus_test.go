package telemetry

import (
	"context"
	"testing"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestBusSnapshotsWatchesAndEvictsOldestFrame(t *testing.T) {
	bus := NewBus(2)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watch := bus.WatchEvents(ctx)
	bus.PublishEvent(busEventFrame(1, "event-1"))
	if got := <-watch; got.GetEvent().GetId() != "event-1" {
		t.Fatalf("watched event=%+v", got)
	}
	bus.PublishEvent(busEventFrame(2, "event-2"))
	bus.PublishEvent(busEventFrame(3, "event-3"))

	snapshot := bus.SnapshotEvents()
	if len(snapshot) != 2 || snapshot[0].GetEvent().GetId() != "event-2" || snapshot[1].GetEvent().GetId() != "event-3" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	stats := bus.Stats()
	if stats.EventEvicted != 1 || stats.EventBuffered != 2 || stats.EventOldestSequence != 2 || stats.EventNewestSequence != 3 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestBusWatchesSignalsAndRemovesCancelledSubscriber(t *testing.T) {
	bus := NewBus(2)
	ctx, cancel := context.WithCancel(t.Context())
	watch := bus.WatchSignals(ctx)
	bus.PublishSignal(&dataplanev1.SignalFrame{Sequence: 4, Signal: &signalv1.Signal{Id: "signal-4"}})
	if got := <-watch; got.GetSignal().GetId() != "signal-4" {
		t.Fatalf("watched signal=%+v", got)
	}
	bus.PublishSignal(&dataplanev1.SignalFrame{Sequence: 5, Signal: &signalv1.Signal{Id: "signal-5"}})
	bus.PublishSignal(&dataplanev1.SignalFrame{Sequence: 6, Signal: &signalv1.Signal{Id: "signal-6"}})
	snapshot := bus.SnapshotSignals()
	if len(snapshot) != 2 || snapshot[0].GetSignal().GetId() != "signal-5" || snapshot[1].GetSignal().GetId() != "signal-6" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for bus.Stats().SignalSubscribers != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := bus.Stats(); stats.SignalSubscribers != 0 || stats.SignalEvicted != 1 || stats.SignalOldestSequence != 5 || stats.SignalNewestSequence != 6 {
		t.Fatalf("stats=%+v", stats)
	}
}

func busEventFrame(sequence uint64, id string) *dataplanev1.EventFrame {
	return &dataplanev1.EventFrame{Sequence: sequence, Event: &eventv1.CanonicalEvent{Id: id}}
}
