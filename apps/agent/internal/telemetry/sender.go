package telemetry

import (
	"context"
	"sync"
	"time"

	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type Sender struct {
	Appender     dataappend.BatchSender
	Batcher      *telemetryadapter.Batcher
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
