package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
	"google.golang.org/protobuf/proto"
)

const (
	defaultBatchSize     = 64
	defaultMaxBytes      = 256 * 1024
	defaultFlushInterval = time.Second
	defaultQueueCapacity = 128
)

type BatchFactory func(time.Time) *dataplanev1.DataBatch

type BatchSettings struct {
	MaxItems      int
	MaxBytes      int
	FlushInterval time.Duration
}

type Batcher struct {
	factory       BatchFactory
	batchSize     int
	maxBytes      int
	flushInterval time.Duration
	queue         chan *dataplanev1.DataBatch

	mu      sync.Mutex
	pending *dataplanev1.DataBatch
	bytes   int
	timer   *time.Timer
	closed  bool
	stats   BatcherStats
}

type BatcherStats struct {
	PendingEvents     uint64
	PendingSignals    uint64
	QueuedBatches     uint64
	QueueCapacity     uint64
	DroppedBatches    uint64
	DroppedEvents     uint64
	DroppedSignals    uint64
	FlushedBatches    uint64
	FlushedEvents     uint64
	FlushedSignals    uint64
	PendingBytes      uint64
	MaxBytes          uint64
	FlushedByCount    uint64
	FlushedByBytes    uint64
	FlushedByInterval uint64
	FlushedByShutdown uint64
	LastFlushReason   string
	LastError         string
	Closed            bool
}

func NewBatcher(factory BatchFactory, batchSize int, flushInterval time.Duration, queueCapacity int, maxBytes ...int) *Batcher {
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	limitBytes := defaultMaxBytes
	if len(maxBytes) > 0 && maxBytes[0] > 0 {
		limitBytes = maxBytes[0]
	}
	if flushInterval <= 0 {
		flushInterval = defaultFlushInterval
	}
	if queueCapacity <= 0 {
		queueCapacity = defaultQueueCapacity
	}
	batcher := &Batcher{
		factory: factory, batchSize: batchSize, maxBytes: limitBytes,
		flushInterval: flushInterval, queue: make(chan *dataplanev1.DataBatch, queueCapacity),
	}
	batcher.timer = time.NewTimer(flushInterval)
	if !batcher.timer.Stop() {
		<-batcher.timer.C
	}
	return batcher
}

func (b *Batcher) Add(batch *dataplanev1.DataBatch) {
	if b == nil || batch == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.recordDroppedLocked(batch, "telemetry batcher closed")
		return
	}
	if b.pending == nil {
		b.pending = b.newBatch(time.Now().UTC())
		b.resetTimerLocked()
	}
	b.pending.Events = append(b.pending.Events, batch.GetEvents()...)
	b.pending.Signals = append(b.pending.Signals, batch.GetSignals()...)
	b.bytes += proto.Size(batch)
	b.updatePendingStatsLocked()
	reason, flush := domaintelemetry.DecideFlush(
		domaintelemetry.Pending{Items: len(b.pending.Events) + len(b.pending.Signals), Bytes: b.bytes},
		domaintelemetry.Limits{MaxItems: b.batchSize, MaxBytes: b.maxBytes},
	)
	if flush {
		b.flushLocked(string(reason))
	}
}

func (b *Batcher) Run(ctx context.Context) {
	if b == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			b.CloseAndFlush("shutdown")
			return
		case <-b.timer.C:
			b.Flush("interval")
		}
	}
}

func (b *Batcher) Flush(reason string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked(reason)
}

func (b *Batcher) FlushAndApply(reason string, apply func()) {
	if b == nil {
		if apply != nil {
			apply()
		}
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked(reason)
	if apply != nil {
		apply()
	}
}

func (b *Batcher) Reconfigure(settings BatchSettings) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked("policy")
	b.batchSize = settings.MaxItems
	b.maxBytes = settings.MaxBytes
	b.flushInterval = settings.FlushInterval
}

func (b *Batcher) CloseAndFlush(reason string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.flushLocked(reason)
	b.closed = true
	b.stats.Closed = true
	close(b.queue)
}

func (b *Batcher) Batches() <-chan *dataplanev1.DataBatch {
	if b == nil {
		queue := make(chan *dataplanev1.DataBatch)
		close(queue)
		return queue
	}
	return b.queue
}

func (b *Batcher) Stats() BatcherStats {
	if b == nil {
		return BatcherStats{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := b.stats
	stats.QueueCapacity = uint64(cap(b.queue))
	stats.QueuedBatches = uint64(len(b.queue))
	stats.MaxBytes = uint64(b.maxBytes)
	stats.Closed = b.closed
	return stats
}

func (b *Batcher) newBatch(now time.Time) *dataplanev1.DataBatch {
	if b.factory != nil {
		return b.factory(now)
	}
	return &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{CreatedAtUnixNano: now.UnixNano()}}
}

func (b *Batcher) flushLocked(reason string) {
	if b.pending == nil || (len(b.pending.Events) == 0 && len(b.pending.Signals) == 0) {
		b.stopTimerLocked()
		return
	}
	batch := b.pending
	finalizeBatch(batch)
	select {
	case b.queue <- batch:
		b.stats.FlushedBatches++
		b.stats.FlushedEvents += uint64(len(batch.Events))
		b.stats.FlushedSignals += uint64(len(batch.Signals))
		b.stats.LastFlushReason = reason
		b.stats.LastError = ""
	default:
		b.recordDroppedLocked(batch, "telemetry batch queue full")
	}
	b.recordFlushReasonLocked(reason)
	b.pending = nil
	b.bytes = 0
	b.updatePendingStatsLocked()
	b.stopTimerLocked()
}

func (b *Batcher) recordDroppedLocked(batch *dataplanev1.DataBatch, message string) {
	b.stats.DroppedBatches++
	b.stats.DroppedEvents += uint64(len(batch.GetEvents()))
	b.stats.DroppedSignals += uint64(len(batch.GetSignals()))
	b.stats.LastError = message
}

func (b *Batcher) updatePendingStatsLocked() {
	b.stats.PendingEvents = uint64(len(b.pending.GetEvents()))
	b.stats.PendingSignals = uint64(len(b.pending.GetSignals()))
	b.stats.PendingBytes = uint64(b.bytes)
}

func (b *Batcher) recordFlushReasonLocked(reason string) {
	switch reason {
	case "count":
		b.stats.FlushedByCount++
	case "bytes":
		b.stats.FlushedByBytes++
	case "interval":
		b.stats.FlushedByInterval++
	case "shutdown":
		b.stats.FlushedByShutdown++
	}
}

func finalizeBatch(batch *dataplanev1.DataBatch) {
	if batch.Header == nil {
		batch.Header = &dataplanev1.BatchHeader{}
	}
	if batch.Header.BatchId == "" {
		batch.Header.BatchId = fmt.Sprintf("%020d", time.Now().UnixNano())
	}
	batch.SchemaVersion = schema.DataPlaneCurrent
	batch.Header.EventCount = uint32(len(batch.Events))
	batch.Header.SignalCount = uint32(len(batch.Signals))
	if len(batch.Events) > 0 {
		batch.Header.EventSeqStart = batch.Events[0].GetSequence()
		batch.Header.EventSeqEnd = batch.Events[len(batch.Events)-1].GetSequence()
	}
	if len(batch.Signals) > 0 {
		batch.Header.SignalSeqStart = batch.Signals[0].GetSequence()
		batch.Header.SignalSeqEnd = batch.Signals[len(batch.Signals)-1].GetSequence()
	}
}

func (b *Batcher) resetTimerLocked() {
	b.stopTimerLocked()
	b.timer.Reset(b.flushInterval)
}

func (b *Batcher) stopTimerLocked() {
	if b.timer == nil || b.timer.Stop() {
		return
	}
	select {
	case <-b.timer.C:
	default:
	}
}
