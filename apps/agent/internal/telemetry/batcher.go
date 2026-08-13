package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/protobuf/proto"
)

const (
	defaultBatchSize     = 64
	defaultMaxBytes      = 256 * 1024
	defaultFlushInterval = time.Second
	defaultQueueCapacity = 128
)

type BatchBuilder func(now time.Time) *dataplanev1.DataBatch

type BatchSettings struct {
	MaxItems      int
	MaxBytes      int
	FlushInterval time.Duration
}

type Batcher struct {
	builder       BatchBuilder
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

func NewBatcher(builder BatchBuilder, batchSize int, flushInterval time.Duration, queueCapacity int, maxBytes ...int) *Batcher {
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
	b := &Batcher{
		builder:       builder,
		batchSize:     batchSize,
		maxBytes:      limitBytes,
		flushInterval: flushInterval,
		queue:         make(chan *dataplanev1.DataBatch, queueCapacity),
	}
	b.timer = time.NewTimer(flushInterval)
	if !b.timer.Stop() {
		<-b.timer.C
	}
	return b
}

func (b *Batcher) Add(batch *dataplanev1.DataBatch) {
	if b == nil || batch == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.stats.DroppedBatches++
		b.stats.DroppedEvents += uint64(len(batch.GetEvents()))
		b.stats.DroppedSignals += uint64(len(batch.GetSignals()))
		b.stats.LastError = "telemetry batcher closed"
		return
	}
	if b.pending == nil {
		b.pending = b.newBatch(time.Now().UTC())
		b.resetTimerLocked()
	}
	addedBytes := proto.Size(batch)
	b.pending.Events = append(b.pending.Events, batch.GetEvents()...)
	b.pending.Signals = append(b.pending.Signals, batch.GetSignals()...)
	b.bytes += addedBytes
	b.stats.PendingEvents = uint64(len(b.pending.Events))
	b.stats.PendingSignals = uint64(len(b.pending.Signals))
	b.stats.PendingBytes = uint64(b.bytes)
	if len(b.pending.Events)+len(b.pending.Signals) >= b.batchSize {
		b.flushLocked("count")
		return
	}
	if b.bytes >= b.maxBytes {
		b.flushLocked("bytes")
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
		ch := make(chan *dataplanev1.DataBatch)
		close(ch)
		return ch
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
	if b.pending != nil {
		stats.PendingEvents = uint64(len(b.pending.Events))
		stats.PendingSignals = uint64(len(b.pending.Signals))
		stats.PendingBytes = uint64(b.bytes)
	}
	return stats
}

func (b *Batcher) newBatch(now time.Time) *dataplanev1.DataBatch {
	if b.builder != nil {
		return b.builder(now)
	}
	return &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{CreatedAtUnixNano: now.UnixNano()}}
}

func (b *Batcher) flushLocked(reason string) {
	if b.pending == nil || (len(b.pending.Events) == 0 && len(b.pending.Signals) == 0) {
		b.stopTimerLocked()
		return
	}
	batch := b.pending
	b.finalizeBatch(batch)
	select {
	case b.queue <- batch:
		b.stats.FlushedBatches++
		b.stats.FlushedEvents += uint64(len(batch.Events))
		b.stats.FlushedSignals += uint64(len(batch.Signals))
		b.stats.LastFlushReason = reason
		b.stats.LastError = ""
	default:
		b.stats.DroppedBatches++
		b.stats.DroppedEvents += uint64(len(batch.Events))
		b.stats.DroppedSignals += uint64(len(batch.Signals))
		b.stats.LastError = "telemetry batch queue full"
	}
	b.recordFlushReasonLocked(reason)
	b.pending = nil
	b.bytes = 0
	b.stats.PendingEvents = 0
	b.stats.PendingSignals = 0
	b.stats.PendingBytes = 0
	b.stopTimerLocked()
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

func (b *Batcher) finalizeBatch(batch *dataplanev1.DataBatch) {
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
	if b.timer == nil {
		return
	}
	b.stopTimerLocked()
	b.timer.Reset(b.flushInterval)
}

func (b *Batcher) stopTimerLocked() {
	if b.timer == nil {
		return
	}
	if !b.timer.Stop() {
		select {
		case <-b.timer.C:
		default:
		}
	}
}

type Sender struct {
	Appender     dataappend.BatchSender
	Batcher      *Batcher
	RetryInitial time.Duration
	RetryMax     time.Duration

	mu    sync.Mutex
	stats SenderStats
}

type SenderStats struct {
	SentBatches     uint64
	SentEvents      uint64
	SentSignals     uint64
	RejectedBatches uint64
	RetriedBatches  uint64
	LastError       string
	Drained         bool
}

func (s *Sender) Run(ctx context.Context) {
	if s == nil || s.Batcher == nil {
		return
	}
	batches := s.Batcher.Batches()
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-batches:
			if !ok {
				s.recordDrained()
				return
			}
			s.sendWithRetry(ctx, batch)
		}
	}
}

func (s *Sender) DrainUntilIdle(ctx context.Context) {
	if s == nil || s.Batcher == nil {
		return
	}
	batches := s.Batcher.Batches()
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-batches:
			if !ok {
				s.recordDrained()
				return
			}
			s.sendWithRetry(ctx, batch)
		}
	}
}

func (s *Sender) Stats() SenderStats {
	if s == nil {
		return SenderStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Sender) sendWithRetry(ctx context.Context, batch *dataplanev1.DataBatch) {
	if s.Appender == nil || batch == nil {
		return
	}
	backoff := s.RetryInitial
	if backoff <= 0 {
		backoff = time.Second
	}
	maxBackoff := s.RetryMax
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	for {
		ack, err := s.Appender.SendBatch(batch)
		if err == nil && dataappend.AckCommitted(ack) {
			s.recordSent(batch)
			return
		}
		if dataappend.AckTerminalRejected(ack) {
			s.recordRejected(ack.GetMessage())
			return
		}
		message := "missing data ack"
		if err != nil {
			message = err.Error()
		}
		if ack != nil && ack.GetMessage() != "" {
			message = ack.GetMessage()
		}
		s.recordRetry(message)
		delay := backoff
		if ack != nil && ack.GetRetryAfterMs() > 0 {
			delay = time.Duration(ack.GetRetryAfterMs()) * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (s *Sender) recordSent(batch *dataplanev1.DataBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.SentBatches++
	s.stats.SentEvents += uint64(len(batch.GetEvents()))
	s.stats.SentSignals += uint64(len(batch.GetSignals()))
	s.stats.LastError = ""
}

func (s *Sender) recordDrained() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Drained = true
}

func (s *Sender) recordRejected(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.RejectedBatches++
	s.stats.LastError = message
}

func (s *Sender) recordRetry(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.RetriedBatches++
	s.stats.LastError = message
}
