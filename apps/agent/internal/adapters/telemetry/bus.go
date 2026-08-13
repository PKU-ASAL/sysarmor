package telemetry

import (
	"context"
	"sync"
	"sync/atomic"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

const defaultBusCapacity = 4096

type Bus struct {
	mu             sync.RWMutex
	capacity       int
	events         []*dataplanev1.EventFrame
	signals        []*dataplanev1.SignalFrame
	eventWatchers  map[uint64]chan *dataplanev1.EventFrame
	signalWatchers map[uint64]chan *dataplanev1.SignalFrame
	nextWatcherID  uint64
	droppedEvents  uint64
	droppedSignals uint64
}

type BusStats struct {
	EventCapacity        uint64
	EventBuffered        uint64
	EventNextSequence    uint64
	EventOldestSequence  uint64
	EventNewestSequence  uint64
	EventDropped         uint64
	EventSubscribers     uint64
	SignalCapacity       uint64
	SignalBuffered       uint64
	SignalNextSequence   uint64
	SignalOldestSequence uint64
	SignalNewestSequence uint64
	SignalDropped        uint64
	SignalSubscribers    uint64
}

func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = defaultBusCapacity
	}
	return &Bus{
		capacity: capacity, eventWatchers: make(map[uint64]chan *dataplanev1.EventFrame),
		signalWatchers: make(map[uint64]chan *dataplanev1.SignalFrame),
	}
}

func (b *Bus) PublishBatch(batch *dataplanev1.DataBatch) {
	if b == nil || batch == nil {
		return
	}
	for _, frame := range batch.GetEvents() {
		b.PublishEvent(frame)
	}
	for _, frame := range batch.GetSignals() {
		b.PublishSignal(frame)
	}
}

func (b *Bus) PublishEvent(frame *dataplanev1.EventFrame) {
	if b == nil || frame == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) >= b.capacity {
		copy(b.events, b.events[1:])
		b.events[len(b.events)-1] = frame
		atomic.AddUint64(&b.droppedEvents, 1)
	} else {
		b.events = append(b.events, frame)
	}
	for id, watcher := range b.eventWatchers {
		select {
		case watcher <- frame:
		default:
			delete(b.eventWatchers, id)
			close(watcher)
		}
	}
}

func (b *Bus) PublishSignal(frame *dataplanev1.SignalFrame) {
	if b == nil || frame == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.signals) >= b.capacity {
		copy(b.signals, b.signals[1:])
		b.signals[len(b.signals)-1] = frame
		atomic.AddUint64(&b.droppedSignals, 1)
	} else {
		b.signals = append(b.signals, frame)
	}
	for id, watcher := range b.signalWatchers {
		select {
		case watcher <- frame:
		default:
			delete(b.signalWatchers, id)
			close(watcher)
		}
	}
}

func (b *Bus) SnapshotEvents() []*dataplanev1.EventFrame {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]*dataplanev1.EventFrame(nil), b.events...)
}

func (b *Bus) SnapshotSignals() []*dataplanev1.SignalFrame {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]*dataplanev1.SignalFrame(nil), b.signals...)
}

func (b *Bus) WatchEvents(ctx context.Context) <-chan *dataplanev1.EventFrame {
	out := make(chan *dataplanev1.EventFrame, 256)
	if b == nil {
		close(out)
		return out
	}
	id := b.addEventWatcher(out)
	go b.removeEventWatcher(ctx, id)
	return out
}

func (b *Bus) WatchSignals(ctx context.Context) <-chan *dataplanev1.SignalFrame {
	out := make(chan *dataplanev1.SignalFrame, 256)
	if b == nil {
		close(out)
		return out
	}
	id := b.addSignalWatcher(out)
	go b.removeSignalWatcher(ctx, id)
	return out
}

func (b *Bus) addEventWatcher(watcher chan *dataplanev1.EventFrame) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextWatcherID++
	b.eventWatchers[b.nextWatcherID] = watcher
	return b.nextWatcherID
}

func (b *Bus) addSignalWatcher(watcher chan *dataplanev1.SignalFrame) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextWatcherID++
	b.signalWatchers[b.nextWatcherID] = watcher
	return b.nextWatcherID
}

func (b *Bus) removeEventWatcher(ctx context.Context, id uint64) {
	<-ctx.Done()
	b.mu.Lock()
	defer b.mu.Unlock()
	if watcher, ok := b.eventWatchers[id]; ok {
		delete(b.eventWatchers, id)
		close(watcher)
	}
}

func (b *Bus) removeSignalWatcher(ctx context.Context, id uint64) {
	<-ctx.Done()
	b.mu.Lock()
	defer b.mu.Unlock()
	if watcher, ok := b.signalWatchers[id]; ok {
		delete(b.signalWatchers, id)
		close(watcher)
	}
}

func (b *Bus) Stats() BusStats {
	if b == nil {
		return BusStats{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	stats := BusStats{
		EventCapacity: uint64(b.capacity), EventBuffered: uint64(len(b.events)), EventDropped: atomic.LoadUint64(&b.droppedEvents), EventSubscribers: uint64(len(b.eventWatchers)),
		SignalCapacity: uint64(b.capacity), SignalBuffered: uint64(len(b.signals)), SignalDropped: atomic.LoadUint64(&b.droppedSignals), SignalSubscribers: uint64(len(b.signalWatchers)),
	}
	if len(b.events) > 0 {
		stats.EventOldestSequence = b.events[0].GetSequence()
		stats.EventNewestSequence = b.events[len(b.events)-1].GetSequence()
		stats.EventNextSequence = stats.EventNewestSequence + 1
	}
	if len(b.signals) > 0 {
		stats.SignalOldestSequence = b.signals[0].GetSequence()
		stats.SignalNewestSequence = b.signals[len(b.signals)-1].GetSequence()
		stats.SignalNextSequence = stats.SignalNewestSequence + 1
	}
	return stats
}
