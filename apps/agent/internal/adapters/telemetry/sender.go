package telemetry

import (
	"context"
	"fmt"
	"io"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/protobuf/proto"
)

type batchSender interface {
	SendBatch(*dataplanev1.DataBatch) (*dataplanev1.DataAck, error)
}

type CloudSender struct{ sender batchSender }

func NewCloudSender(sender batchSender) *CloudSender {
	return &CloudSender{sender: sender}
}

func (sender *CloudSender) Send(_ context.Context, batch domaintelemetry.Batch) (domaintelemetry.DeliveryOutcome, error) {
	if sender == nil || sender.sender == nil {
		return 0, fmt.Errorf("telemetry sender is not configured")
	}
	wire := &dataplanev1.DataBatch{}
	if err := proto.Unmarshal(batch.Payload, wire); err != nil {
		return 0, fmt.Errorf("decode telemetry batch %s: %w", batch.ID, err)
	}
	ack, err := sender.sender.SendBatch(wire)
	if err != nil {
		return 0, err
	}
	return deliveryOutcome(ack), nil
}

func (sender *CloudSender) Close() error {
	if sender == nil || sender.sender == nil {
		return nil
	}
	if closer, ok := sender.sender.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func deliveryOutcome(ack *dataplanev1.DataAck) domaintelemetry.DeliveryOutcome {
	if ack == nil {
		return domaintelemetry.DeliveryRetryable
	}
	switch ack.GetStatus() {
	case dataplanev1.DataAck_STATUS_ACCEPTED:
		return domaintelemetry.DeliveryAccepted
	case dataplanev1.DataAck_STATUS_DUPLICATE:
		return domaintelemetry.DeliveryDuplicate
	case dataplanev1.DataAck_STATUS_RETRYABLE:
		return domaintelemetry.DeliveryRetryable
	default:
		return domaintelemetry.DeliveryRejected
	}
}
