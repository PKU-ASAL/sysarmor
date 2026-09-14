package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestRuntimeSenderRecordsAcceptedBatch(t *testing.T) {
	batcher := NewBatcher(nil, 1, time.Hour, 1)
	sender := NewRuntimeSender(batcher, acceptedAppender{}, time.Second, time.Second)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})
	batcher.CloseAndFlush("shutdown")

	sender.Run(t.Context())

	stats := sender.Stats()
	if stats.SentBatches != 1 || stats.SentEvents != 1 || !stats.Drained {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRuntimeSenderDrainsClosedBatcher(t *testing.T) {
	batcher := NewBatcher(nil, 10, time.Hour, 1)
	sender := NewRuntimeSender(batcher, acceptedAppender{}, time.Second, time.Second)
	batcher.Add(&dataplanev1.DataBatch{Signals: []*dataplanev1.SignalFrame{{Sequence: 1}}})
	batcher.CloseAndFlush("shutdown")

	sender.DrainUntilIdle(t.Context())

	stats := sender.Stats()
	if stats.SentBatches != 1 || stats.SentSignals != 1 || !stats.Drained {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestBatchTransmitterPreservesAckWhenTransportReturnsError(t *testing.T) {
	result, err := (batchTransmitter{appender: rejectedAppender{}}).Send(t.Context(), &dataplanev1.DataBatch{})
	if err == nil || result.Outcome != domaintelemetry.DeliveryRejected || result.Message != "invalid" || result.RetryAfter != 25*time.Millisecond {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSendResultMapsCommittedAckVariants(t *testing.T) {
	tests := []struct {
		name string
		ack  *dataplanev1.DataAck
		want domaintelemetry.DeliveryOutcome
	}{
		{name: "accepted", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_ACCEPTED}, want: domaintelemetry.DeliveryAccepted},
		{name: "duplicate", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_DUPLICATE}, want: domaintelemetry.DeliveryDuplicate},
		{name: "legacy accepted", ack: &dataplanev1.DataAck{Accepted: true}, want: domaintelemetry.DeliveryAccepted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sendResult(test.ack).Outcome; got != test.want {
				t.Fatalf("outcome=%d want=%d", got, test.want)
			}
		})
	}
}

func TestRuntimeSenderReportsMissingAckAndDoesNotMarkCancelledSourceDrained(t *testing.T) {
	batcher := NewBatcher(nil, 1, time.Hour, 1)
	sender := NewRuntimeSender(batcher, missingAckAppender{}, time.Millisecond, time.Millisecond)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		sender.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for sender.Stats().RetriedBatches == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	stats := sender.Stats()
	if stats.RetriedBatches == 0 || stats.LastError != "missing data ack" || stats.Drained {
		t.Fatalf("stats=%+v", stats)
	}
}

type acceptedAppender struct{}

func (acceptedAppender) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	return &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_ACCEPTED, BatchId: batch.GetHeader().GetBatchId()}, nil
}

type rejectedAppender struct{}

func (rejectedAppender) SendBatch(*dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	return &dataplanev1.DataAck{
		Status: dataplanev1.DataAck_STATUS_REJECTED, Message: "invalid", RetryAfterMs: 25,
	}, errors.New("transport closed")
}

type missingAckAppender struct{}

func (missingAckAppender) SendBatch(*dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	return nil, nil
}
