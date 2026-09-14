package telemetry

import (
	"context"
	"sync"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
)

type Source[T any] interface {
	Next(context.Context) (T, bool)
}

type Transmitter[T any] interface {
	Send(context.Context, T) (domaintelemetry.SendResult, error)
}

type SenderOptions[T any] struct {
	RetryInitial time.Duration
	RetryMax     time.Duration
	Measure      func(T) (events, signals uint64)
	Wait         func(context.Context, time.Duration) bool
}

type Sender[T any] struct {
	source      Source[T]
	transmitter Transmitter[T]
	options     SenderOptions[T]

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

func NewSender[T any](source Source[T], transmitter Transmitter[T], options SenderOptions[T]) *Sender[T] {
	return &Sender[T]{source: source, transmitter: transmitter, options: options}
}

func (sender *Sender[T]) Run(ctx context.Context) {
	if sender == nil || sender.source == nil {
		return
	}
	for {
		batch, ok := sender.source.Next(ctx)
		if !ok {
			if ctx.Err() == nil {
				sender.recordDrained()
			}
			return
		}
		sender.sendWithRetry(ctx, batch)
	}
}

func (sender *Sender[T]) DrainUntilIdle(ctx context.Context) { sender.Run(ctx) }

func (sender *Sender[T]) Stats() SenderStats {
	if sender == nil {
		return SenderStats{}
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return sender.stats
}

func (sender *Sender[T]) sendWithRetry(ctx context.Context, batch T) {
	if sender.transmitter == nil {
		return
	}
	backoff, maxBackoff := retryLimits(sender.options)
	for {
		result, err := sender.transmitter.Send(ctx, batch)
		if err == nil && (result.Outcome == domaintelemetry.DeliveryAccepted || result.Outcome == domaintelemetry.DeliveryDuplicate) {
			sender.recordSent(batch)
			return
		}
		if result.Outcome == domaintelemetry.DeliveryRejected {
			sender.recordRejected(result.Message)
			return
		}
		message := result.Message
		if message == "" && err != nil {
			message = err.Error()
		}
		sender.recordRetry(message)
		delay := backoff
		if result.RetryAfter > 0 {
			delay = result.RetryAfter
		}
		if !sender.wait(ctx, delay) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func retryLimits[T any](options SenderOptions[T]) (time.Duration, time.Duration) {
	initial := options.RetryInitial
	if initial <= 0 {
		initial = time.Second
	}
	maximum := options.RetryMax
	if maximum <= 0 {
		maximum = 30 * time.Second
	}
	return initial, maximum
}

func (sender *Sender[T]) wait(ctx context.Context, delay time.Duration) bool {
	if sender.options.Wait != nil {
		return sender.options.Wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (sender *Sender[T]) recordSent(batch T) {
	events, signals := uint64(0), uint64(0)
	if sender.options.Measure != nil {
		events, signals = sender.options.Measure(batch)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.stats.SentBatches++
	sender.stats.SentEvents += events
	sender.stats.SentSignals += signals
	sender.stats.LastError = ""
}

func (sender *Sender[T]) recordDrained() {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.stats.Drained = true
}

func (sender *Sender[T]) recordRejected(message string) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.stats.RejectedBatches++
	sender.stats.LastError = message
}

func (sender *Sender[T]) recordRetry(message string) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.stats.RetriedBatches++
	sender.stats.LastError = message
}
