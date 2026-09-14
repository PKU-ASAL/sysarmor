package telemetry

import (
	"context"
	"time"

	applicationtelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/telemetry"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type batchAppender interface {
	SendBatch(*dataplanev1.DataBatch) (*dataplanev1.DataAck, error)
}

type RuntimeSender struct {
	service *applicationtelemetry.Sender[*dataplanev1.DataBatch]
}

func NewRuntimeSender(batcher *Batcher, appender batchAppender, retryInitial, retryMax time.Duration) *RuntimeSender {
	var transmitter applicationtelemetry.Transmitter[*dataplanev1.DataBatch]
	if appender != nil {
		transmitter = batchTransmitter{appender: appender}
	}
	return &RuntimeSender{service: applicationtelemetry.NewSender(
		batchSource{batches: batcher.Batches()}, transmitter,
		applicationtelemetry.SenderOptions[*dataplanev1.DataBatch]{
			RetryInitial: retryInitial,
			RetryMax:     retryMax,
			Measure: func(batch *dataplanev1.DataBatch) (uint64, uint64) {
				return uint64(len(batch.GetEvents())), uint64(len(batch.GetSignals()))
			},
		},
	)}
}

func (sender *RuntimeSender) Run(ctx context.Context) {
	if sender != nil {
		sender.service.Run(ctx)
	}
}

func (sender *RuntimeSender) DrainUntilIdle(ctx context.Context) {
	if sender != nil {
		sender.service.DrainUntilIdle(ctx)
	}
}

func (sender *RuntimeSender) Stats() applicationtelemetry.SenderStats {
	if sender == nil {
		return applicationtelemetry.SenderStats{}
	}
	return sender.service.Stats()
}

type batchSource struct {
	batches <-chan *dataplanev1.DataBatch
}

func (source batchSource) Next(ctx context.Context) (*dataplanev1.DataBatch, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	case batch, ok := <-source.batches:
		return batch, ok
	}
}

type batchTransmitter struct {
	appender batchAppender
}

func (sender batchTransmitter) Send(_ context.Context, batch *dataplanev1.DataBatch) (domaintelemetry.SendResult, error) {
	ack, err := sender.appender.SendBatch(batch)
	return sendResult(ack), err
}

func sendResult(ack *dataplanev1.DataAck) domaintelemetry.SendResult {
	if ack == nil {
		return domaintelemetry.SendResult{Outcome: domaintelemetry.DeliveryRetryable, Message: "missing data ack"}
	}
	result := domaintelemetry.SendResult{
		Outcome:    domaintelemetry.DeliveryRetryable,
		RetryAfter: time.Duration(ack.GetRetryAfterMs()) * time.Millisecond,
		Message:    ack.GetMessage(),
	}
	switch ack.GetStatus() {
	case dataplanev1.DataAck_STATUS_ACCEPTED:
		result.Outcome = domaintelemetry.DeliveryAccepted
	case dataplanev1.DataAck_STATUS_DUPLICATE:
		result.Outcome = domaintelemetry.DeliveryDuplicate
	case dataplanev1.DataAck_STATUS_REJECTED:
		if !ack.GetRetryable() {
			result.Outcome = domaintelemetry.DeliveryRejected
		}
	case dataplanev1.DataAck_STATUS_UNSPECIFIED:
		if ack.GetAccepted() {
			result.Outcome = domaintelemetry.DeliveryAccepted
		}
	}
	return result
}
