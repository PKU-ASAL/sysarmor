package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
)

func TestSenderRetriesThenRecordsAcceptedBatch(t *testing.T) {
	source := &sourceFake[string]{items: []string{"batch-a"}}
	transmitter := &transmitterFake[string]{results: []domaintelemetry.SendResult{
		{Outcome: domaintelemetry.DeliveryRetryable, RetryAfter: 25 * time.Millisecond, Message: "busy"},
		{Outcome: domaintelemetry.DeliveryAccepted},
	}}
	var waits []time.Duration
	sender := NewSender(source, transmitter, SenderOptions[string]{
		RetryInitial: time.Second,
		Measure:      func(string) (uint64, uint64) { return 2, 1 },
		Wait: func(_ context.Context, delay time.Duration) bool {
			waits = append(waits, delay)
			return true
		},
	})

	sender.Run(t.Context())

	stats := sender.Stats()
	if transmitter.calls != 2 || len(waits) != 1 || waits[0] != 25*time.Millisecond {
		t.Fatalf("calls=%d waits=%v", transmitter.calls, waits)
	}
	if stats.RetriedBatches != 1 || stats.SentBatches != 1 || stats.SentEvents != 2 || stats.SentSignals != 1 || !stats.Drained || stats.LastError != "" {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestSenderStopsRetryingTerminalRejectedBatch(t *testing.T) {
	source := &sourceFake[string]{items: []string{"batch-a"}}
	transmitter := &transmitterFake[string]{results: []domaintelemetry.SendResult{{
		Outcome: domaintelemetry.DeliveryRejected, Message: "invalid",
	}}}
	sender := NewSender(source, transmitter, SenderOptions[string]{Wait: func(context.Context, time.Duration) bool { return false }})

	sender.Run(t.Context())

	stats := sender.Stats()
	if transmitter.calls != 1 || stats.RejectedBatches != 1 || stats.LastError != "invalid" || !stats.Drained {
		t.Fatalf("calls=%d stats=%+v", transmitter.calls, stats)
	}
}

func TestSenderTreatsTerminalRejectionAsFinalEvenWithTransportError(t *testing.T) {
	source := &sourceFake[string]{items: []string{"batch-a"}}
	transmitter := &transmitterFake[string]{
		results: []domaintelemetry.SendResult{{Outcome: domaintelemetry.DeliveryRejected, Message: "invalid"}},
		errors:  []error{errors.New("transport closed")},
	}
	sender := NewSender(source, transmitter, SenderOptions[string]{})

	sender.Run(t.Context())

	stats := sender.Stats()
	if transmitter.calls != 1 || stats.RejectedBatches != 1 || stats.RetriedBatches != 0 || stats.LastError != "invalid" {
		t.Fatalf("calls=%d stats=%+v", transmitter.calls, stats)
	}
}

type sourceFake[T any] struct {
	items []T
	next  int
}

func (source *sourceFake[T]) Next(context.Context) (T, bool) {
	if source.next >= len(source.items) {
		var zero T
		return zero, false
	}
	item := source.items[source.next]
	source.next++
	return item, true
}

type transmitterFake[T any] struct {
	results []domaintelemetry.SendResult
	errors  []error
	calls   int
}

func (sender *transmitterFake[T]) Send(context.Context, T) (domaintelemetry.SendResult, error) {
	index := sender.calls
	result := sender.results[min(index, len(sender.results)-1)]
	sender.calls++
	if len(sender.errors) == 0 {
		return result, nil
	}
	return result, sender.errors[min(index, len(sender.errors)-1)]
}
